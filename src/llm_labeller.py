"""
llm_labeller.py — label unlabelled projects via Anthropic API.

For each project without keyword-matched labels, we send:
  - README.md           (protocol context)
  - up to 5 largest non-test .sol files (capped at 80k chars total)
  - 4naly3er-report.md  (if present — automated static analysis baseline)

The LLM returns JSON: {"Tag Name": ["Subtag A", "Subtag B"], ...}
Only tags that genuinely apply should be included.

Usage:
    python -m src.llm_labeller                      # labels all unlabelled
    python -m src.llm_labeller --project <id>       # single project

Output: dataset/llm_labels.csv  (same schema as train_labels.csv)

Requires:
    ANTHROPIC_API_KEY environment variable
    pip install anthropic
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from taxonomy import TAGS, SUBTAGS  # noqa: E402

TRAIN_DIR       = _ROOT / "dataset" / "train" / "train"
TRAIN_LABELS    = _ROOT / "dataset" / "train_labels.csv"
LLM_LABELS_OUT  = _ROOT / "dataset" / "llm_labels.csv"

_MODEL          = "claude-haiku-4-5-20251001"
_CHAR_BUDGET    = 300_000  # total chars of sol files per project (~75k tokens)
_MAX_SOL_FILES  = 10
_RETRY_WAIT     = 30       # seconds to wait on rate-limit error

# dirs / suffixes that indicate test / non-production code
_TEST_MARKERS = {"test", "tests", "mock", "mocks", "script", "scripts", "forge-std", "out", "artifacts", "cache"}


# ─────────────────────────────────────────────────────────────────────────────
# Taxonomy prompt fragment
# ─────────────────────────────────────────────────────────────────────────────

def _build_taxonomy_block() -> str:
    lines = ["VULNERABILITY TAXONOMY (38 tags):", ""]
    for tag, info in TAGS.items():
        subtag_names = info["subtags"]
        subtag_str   = ", ".join(f'"{s}"' for s in subtag_names) if subtag_names else "none"
        lines.append(f'  Tag: "{tag}"')
        lines.append(f'    Description: {info["description"]}')
        lines.append(f'    Valid subtags: {subtag_str}')
        lines.append("")
    return "\n".join(lines)


_TAXONOMY_BLOCK = _build_taxonomy_block()


# ─────────────────────────────────────────────────────────────────────────────
# File collection
# ─────────────────────────────────────────────────────────────────────────────

def _collect_sol_files(project_dir: Path) -> list[Path]:
    """Return non-test .sol files sorted by size descending."""
    candidates = []
    for sol in project_dir.rglob("*.sol"):
        if not sol.is_file():
            continue
        # skip if any path component looks like a test directory
        parts_lower = {p.lower() for p in sol.parts}
        if parts_lower & _TEST_MARKERS:
            continue
        candidates.append(sol)
    return sorted(candidates, key=lambda p: p.stat().st_size, reverse=True)


def _build_context(project_dir: Path) -> str:
    """
    Assemble the project context string to send to Claude:
      1. README.md
      2. 4naly3er-report.md (if present)
      3. Up to _MAX_SOL_FILES .sol files within _CHAR_BUDGET chars
    """
    sections: list[str] = []

    readme = project_dir / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8", errors="ignore")[:8_000]
        sections.append(f"=== README.md ===\n{text}")

    naly = project_dir / "4naly3er-report.md"
    if naly.exists():
        text = naly.read_text(encoding="utf-8", errors="ignore")[:12_000]
        sections.append(f"=== 4naly3er-report.md ===\n{text}")

    remaining = _CHAR_BUDGET
    sol_count = 0
    for sol in _collect_sol_files(project_dir):
        if sol_count >= _MAX_SOL_FILES or remaining <= 0:
            break
        text = sol.read_text(encoding="utf-8", errors="ignore")
        chunk = text[:remaining]
        rel   = sol.relative_to(project_dir)
        sections.append(f"=== {rel} ===\n{chunk}")
        remaining  -= len(chunk)
        sol_count  += 1

    return "\n\n".join(sections)


# ─────────────────────────────────────────────────────────────────────────────
# Prompt
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM = """\
You are a smart contract security auditor. Given source files from an audit project \
and a vulnerability taxonomy, identify individual vulnerabilities present in the code.

For each distinct vulnerability you find, output one JSON object in an array.

Rules:
- Report each vulnerability as a separate finding — do not merge unrelated issues.
- Only include tags from the provided taxonomy; only include subtags from that tag's valid list.
- severity must be exactly one of: "Critical", "High", "Medium", "Low".
- Every finding MUST be grounded in a concrete, specific code pattern you can observe in \
the provided files — name the function, variable, or code path involved.
- Only include vulnerabilities you are confident exist based on the provided code. \
Do not include hypothetical, speculative, or generic issues that could apply to any contract.
- If you are uncertain whether something is truly a vulnerability, omit it.
- description must be a precise explanation (1–3 sentences) citing the specific \
function/contract and root cause. Generic descriptions like "missing access control" \
with no code reference are not acceptable.
- Respond ONLY with a valid JSON array. No prose, no markdown fences.

Response format:
[
  {
    "severity": "High",
    "tag": "Tag Name",
    "subtags": ["Subtag A", "Subtag B"],
    "description": "Specific description of the vulnerability in this code."
  }
]"""


def _build_user_message(project_dir: Path) -> str:
    context = _build_context(project_dir)
    return f"{_TAXONOMY_BLOCK}\n\n---\n\nPROJECT FILES:\n\n{context}"


# ─────────────────────────────────────────────────────────────────────────────
# API call
# ─────────────────────────────────────────────────────────────────────────────

def _call_llm(user_message: str, *, retries: int = 3) -> str:
    try:
        import anthropic
    except ImportError:
        raise SystemExit("anthropic not installed — run: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise SystemExit("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)

    for attempt in range(retries):
        try:
            response = client.messages.create(
                model=_MODEL,
                max_tokens=4096,
                system=_SYSTEM,
                messages=[{"role": "user", "content": user_message}],
            )
            return response.content[0].text
        except Exception as e:
            err = str(e).lower()
            if ("rate" in err or "quota" in err or "429" in err or "overloaded" in err) and attempt < retries - 1:
                print(f"  [rate limit] waiting {_RETRY_WAIT}s …")
                time.sleep(_RETRY_WAIT)
            else:
                raise

    raise RuntimeError("exceeded retries")


# ─────────────────────────────────────────────────────────────────────────────
# Parse response
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _parse_response(raw: str, project_id: str) -> list[dict]:
    """Parse LLM JSON array into per-finding label rows. Validates against taxonomy."""
    text = raw.strip()
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    text = "\n".join(lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  [warn] JSON parse error for {project_id}: {e}")
        print(f"  raw response: {raw[:300]}")
        return []

    if not isinstance(data, list):
        print(f"  [warn] {project_id}: expected JSON array, got {type(data).__name__}")
        return []

    rows = []
    for item in data:
        tag = item.get("tag", "")
        if tag not in TAGS:
            print(f"  [warn] {project_id}: unknown tag '{tag}' — skipping")
            continue

        severity = item.get("severity", "Medium")
        if severity not in _VALID_SEVERITIES:
            severity = "Medium"

        subtags = item.get("subtags") or []
        valid_subtags = set(TAGS[tag]["subtags"])
        clean_subtags = [s for s in subtags if s in valid_subtags]
        invalid = [s for s in subtags if s not in valid_subtags]
        if invalid:
            print(f"  [warn] {project_id}/{tag}: dropped invalid subtags {invalid}")

        rows.append({
            "project_id":  project_id,
            "severity":    severity,
            "tag":         tag,
            "subtags":     sorted(clean_subtags),
            "description": str(item.get("description", "")).strip(),
            "source":      "llm",
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Main labelling loop
# ─────────────────────────────────────────────────────────────────────────────

def _unlabelled_projects(train_dir: Path) -> list[str]:
    labelled: set[str] = set()
    if TRAIN_LABELS.exists():
        labelled = set(pd.read_csv(TRAIN_LABELS)["project_id"].unique())
    if LLM_LABELS_OUT.exists():
        labelled |= set(pd.read_csv(LLM_LABELS_OUT)["project_id"].unique())
    all_projects = sorted(p.name for p in train_dir.iterdir() if p.is_dir())
    return [pid for pid in all_projects if pid not in labelled]


def label_projects(
    project_ids: list[str] | None = None,
    train_dir: Path = TRAIN_DIR,
) -> pd.DataFrame:
    """
    Label projects via Anthropic API, producing per-finding rows.

    Args:
        project_ids: explicit list of IDs to label; if None, labels all unlabelled.
        train_dir:   path to the train split.

    Returns:
        DataFrame with columns: project_id, severity, tag, subtags, description, source.
        Also saved to llm_labels.csv.
    """
    if project_ids is None:
        project_ids = _unlabelled_projects(train_dir)

    if not project_ids:
        print("No unlabelled projects found.")
        return pd.DataFrame()

    print(f"Labelling {len(project_ids)} projects with {_MODEL} …\n")

    all_rows: list[dict] = []

    for i, pid in enumerate(project_ids, 1):
        proj_dir = train_dir / pid
        print(f"[{i}/{len(project_ids)}] {pid}")

        user_msg = _build_user_message(proj_dir)
        print(f"  context chars: {len(user_msg):,}")

        try:
            raw = _call_llm(user_msg)
        except Exception as e:
            print(f"  [error] API call failed: {e}")
            continue

        rows = _parse_response(raw, pid)
        print(f"  → {len(rows)} findings: {[r['tag'] for r in rows]}")
        all_rows.extend(rows)

    df = pd.DataFrame(all_rows)

    if not df.empty:
        if LLM_LABELS_OUT.exists():
            existing = pd.read_csv(LLM_LABELS_OUT)
            df = pd.concat([existing, df], ignore_index=True)
            # deduplicate on content — same project+severity+tag+description
            df = df.drop_duplicates(subset=["project_id", "severity", "tag", "description"])

        df.to_csv(LLM_LABELS_OUT, index=False)
        print(f"\nSaved {len(df)} rows → {LLM_LABELS_OUT}")

    return df


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM-based label extractor")
    parser.add_argument("--project", nargs="+", metavar="ID",
                        help="label specific project ID(s); default: all unlabelled")
    parser.add_argument("--train-dir", type=Path, default=TRAIN_DIR)
    args = parser.parse_args()

    label_projects(project_ids=args.project, train_dir=args.train_dir)
