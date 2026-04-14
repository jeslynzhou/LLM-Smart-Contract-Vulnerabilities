"""
label_extractor.py — extract per-finding vulnerability labels from train audit artefacts.

Pipeline per project:
  1. Collect audit text  (PDFs → pdfplumber, markdown/txt → read directly)
  2. Split into individual findings (with severity inferred from heading code)
  3. Match each finding to taxonomy tags + subtags via keyword index
  4. Emit one row per (project_id, finding, tag): severity, tag, subtags, description

Main entry point:
    from src.label_extractor import build_labels
    df = build_labels(TRAIN_DIR)   # returns a DataFrame
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterator

import pandas as pd

# ── project root so imports work regardless of cwd ───────────────────────────
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from taxonomy import TAGS, SUBTAGS  # noqa: E402

TRAIN_DIR = _ROOT / "dataset" / "train" / "train"
TEST_DIR  = _ROOT / "dataset" / "test"  / "test"

# ── audit file patterns to collect ───────────────────────────────────────────
_PDF_GLOBS  = ["audit/**/*.pdf", "audits/**/*.pdf"]
_MD_GLOBS   = ["bot-report.md", "4naly3er-report.md", "slither/**/*.md"]
_JSON_GLOBS = ["bot-report.json"]

_SKIP_DIRS  = {"lib", "node_modules", "__MACOSX", ".git", "ISSUE_TEMPLATE"}
_SKIP_NAMES = {".github", "bug_report.md", "audit-item.md"}

# Finding code letter → severity; letters not in this map are skipped (Gas, Note, Info)
_SEVERITY_CODE: dict[str, str] = {
    "C": "Critical",
    "H": "High",
    "M": "Medium",
    "L": "Low",
}
_SKIP_CODES = {"G", "N", "I", "R"}  # Gas / Note / Info / Refactor


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Text extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_pdf(path: Path) -> str:
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        print(f"[warn] pdfplumber not installed — skipping {path.name}")
        return ""
    try:
        with pdfplumber.open(path) as pdf:
            pages = [p.extract_text() or "" for p in pdf.pages]
        return "\n".join(pages)
    except Exception as e:
        print(f"[warn] PDF extraction failed for {path.name}: {e}")
        return ""


def _extract_md(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[warn] Could not read {path}: {e}")
        return ""


def _extract_bot_json(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        findings = data.get("findings", [])
        parts = []
        for f in findings:
            title = f.get("title", "")
            desc  = f.get("description", "")
            parts.append(f"{title}\n{desc}")
        return "\n\n".join(parts)
    except Exception as e:
        print(f"[warn] Could not parse {path.name}: {e}")
        return ""


def _collect_audit_files(project_dir: Path) -> list[Path]:
    seen: set[Path] = set()
    results: list[Path] = []

    for pattern in _PDF_GLOBS + _MD_GLOBS + _JSON_GLOBS:
        for p in project_dir.glob(pattern):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.name in _SKIP_NAMES:
                continue
            if p not in seen:
                seen.add(p)
                results.append(p)

    discord_dir = project_dir / "discord-export"
    if discord_dir.is_dir():
        for p in discord_dir.iterdir():
            if p.suffix == ".txt" and p not in seen:
                seen.add(p)
                results.append(p)

    return results


def extract_audit_text(project_dir: Path) -> str:
    parts: list[str] = []
    for f in _collect_audit_files(project_dir):
        if f.suffix == ".pdf":
            parts.append(_extract_pdf(f))
        elif f.suffix == ".json":
            parts.append(_extract_bot_json(f))
        else:
            parts.append(_extract_md(f))
    return "\n\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# 2.  Finding splitting — returns dicts with severity, title, text
# ─────────────────────────────────────────────────────────────────────────────

# Markdown findings: ## [H-01] Title  /  ### M-02: Title  /  **[L-03]** Title
_FINDING_RE = re.compile(
    r"^(#{1,4}|\*{2})\s*\[?([A-Z]-\d+[a-z]?)\]?\*{0,2}\s*[:\-–]?\s*(.*)",
    re.IGNORECASE | re.MULTILINE,
)

# PDF numbered findings: "5.1.1 Title" / "5.2.3 Title"
_PDF_FINDING_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)\s+(.+)"
)

# PDF section headers that set severity context: "5.1 Critical Risk" / "## High Risk Issues"
_SECTION_RE = re.compile(
    r"^(?:#{1,4}|\d+(?:\.\d+)*)\s+(Critical|High|Medium|Low)\s*Risk",
    re.IGNORECASE,
)

# Inline severity tag inside a finding body: "Severity: CriticalRisk" / "Severity: High Risk"
_INLINE_SEV_RE = re.compile(
    r"^Severity:\s*(Critical\s*Risk|High\s*Risk|Medium\s*Risk|Low\s*Risk|Critical|High|Medium|Low)",
    re.IGNORECASE,
)

_SEV_NORMALISE = {
    "criticalrisk": "Critical", "critical": "Critical",
    "highrisk":     "High",     "high":     "High",
    "mediumrisk":   "Medium",   "medium":   "Medium",
    "lowrisk":      "Low",      "low":      "Low",
}

# PDF section index → severity (1=Critical, 2=High, 3=Medium, 4=Low, 5+=skip)
_PDF_SECTION_SEV = {"1": "Critical", "2": "High", "3": "Medium", "4": "Low"}


def split_findings(text: str) -> list[dict]:
    """
    Split audit text into finding dicts: {severity, title, text}.
    Handles both markdown (bot-reports) and PDF (Spearbit-style) formats.
    Gas / Note / Info findings are skipped.
    Falls back to a single block (severity=Medium) if no headings found.
    """
    lines = text.splitlines()
    findings: list[dict] = []

    current_severity: str | None = None
    current_title:    str | None = None
    current_code:     str | None = None  # only set for markdown findings
    current_lines:    list[str]  = []
    
    def _flush() -> None:
        if current_title is None:
            return
        # skip Gas/Note/Info markdown findings
        if current_code in _SKIP_CODES:
            return
        findings.append({
            "severity": current_severity or "Medium",
            "title":    current_title,
            "text":     "\n".join(current_lines).strip(),
        })

    for line in lines:
        # ── Section-level severity context ────────────────────────────────────
        sm = _SECTION_RE.match(line)
        if sm:
            # Flush the previous finding before changing the severity context,
            # otherwise the last finding in a section gets the next section's severity.
            _flush()
            current_title  = None
            current_code   = None
            current_lines  = []
            sev_word = sm.group(1).strip().capitalize()
            current_severity = _SEV_NORMALISE.get(sev_word.lower(), sev_word)
            continue

        # ── Inline per-finding severity tag (PDFs) ────────────────────────────
        im = _INLINE_SEV_RE.match(line)
        if im and current_title is not None:
            key = im.group(1).lower().replace(" ", "")
            current_severity = _SEV_NORMALISE.get(key, current_severity)
            continue

        # ── Markdown finding heading ──────────────────────────────────────────
        hm = _FINDING_RE.match(line)
        if hm:
            _flush()
            code_str        = hm.group(2).upper()
            code_letter     = code_str[0]
            current_code    = code_letter
            current_title   = hm.group(3).strip() or code_str
            current_lines   = []
            if code_letter in _SEVERITY_CODE:
                current_severity = _SEVERITY_CODE[code_letter]
            continue

        # ── PDF numbered finding heading: "5.1.1 Title" ───────────────────────
        pm = _PDF_FINDING_RE.match(line)
        if pm:
            section_idx = pm.group(2)   # e.g. "1" in 5.1.3
            title_text  = pm.group(4).strip()
            # skip table-of-contents entries (contain ". . ." dot leaders)
            if ". . " in title_text or title_text.endswith("."):
                current_lines.append(line)
                continue
            _flush()
            current_title   = title_text
            current_code    = None
            current_lines   = []
            # Use section index for severity; keep existing if section unknown
            if section_idx in _PDF_SECTION_SEV:
                current_severity = _PDF_SECTION_SEV[section_idx]
            continue

        current_lines.append(line)

    _flush()

    if not findings:
        findings = [{"severity": "Medium", "title": "", "text": text.strip()}]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 3.  Description extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_description(title: str, body: str) -> str:
    """Return a concise human-readable description for a finding."""
    prefix = f"{title}: " if title else ""
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para:
            continue
        # Skip code blocks, tables, and boilerplate lines
        if para.startswith("```") or para.startswith("|") or para.startswith("*There are"):
            continue
        if re.match(r"^\s*\[?\d+\]?\s*$", para):
            continue
        # Light markdown cleanup
        clean = re.sub(r"\*+", "", para)
        clean = re.sub(r"`([^`]+)`", r"\1", clean)
        clean = re.sub(r"\s+", " ", clean).strip()
        if len(clean) > 20:
            return (prefix + clean)[:500]
    return prefix.rstrip(": ")


# ─────────────────────────────────────────────────────────────────────────────
# 4.  Keyword index + matching
# ─────────────────────────────────────────────────────────────────────────────

_TAG_ALIASES: dict[str, list[str]] = {
    "DoS":                   ["denial of service", "dos", "locked funds",
                               "griefing", "unbounded loop", "out of gas"],
    "Flashloan":             ["flash loan", "flashloan", "flash-loan"],
    "Oracle":                ["oracle", "price feed", "data feed", "chainlink price"],
    "Logic error":           ["logic error", "logical error", "incorrect logic",
                               "wrong logic", "flawed logic"],
    "Reentrancy":            ["reentrancy", "re-entrancy", "nonreentrant",
                               "checks-effects-interactions", "cei pattern"],
    "Access Control":        ["access control", "unauthorized", "privilege",
                               "missing modifier", "onlyowner", "missing access"],
    "Liquidation":           ["liquidat"],
    "Slippage":              ["slippage", "minout", "min out", "sandwich",
                               "price impact", "deadline"],
    "ERC4626":               ["erc4626", "eip-4626", "eip 4626", "vault share",
                               "inflation attack"],
    "Input Validation":      ["input validation", "missing check", "missing validat",
                               "lacks validat", "no check"],
    "Bad Randomness":        ["randomness", "predictable random", "block.timestamp seed",
                               "blockhash", "entropy"],
    "Chainlink":             ["chainlink", "latestrounddata", "latestanswer",
                               "stale price", "sequencer uptime"],
    "Arithmetic":            ["overflow", "underflow", "integer overflow",
                               "arithmetic", "division by zero", "unsafe cast",
                               "unsafe downcast", "precision loss"],
    "Re-org Attack":         ["re-org", "reorg", "chain reorg", "reorganization"],
    "Pause":                 ["pausable", "whenpaused", "whennotpaused"],
    "Accounting Error":      ["accounting error", "balance mismatch",
                               "fee on transfer", "rebas"],
    "MEV":                   ["mev", "maximal extractable", "sandwich attack",
                               "transaction ordering"],
    "Upgradeable":           ["upgradeable", "proxy", "storage gap", "uups",
                               "transparent proxy", "beacon proxy"],
    "ERC20":                 ["erc20", "eip-20", "safetransfer", "safeapprove"],
    "call / delegatecall":   ["delegatecall", "low-level call", "unchecked call"],
    "Uniswap":               ["uniswap", "sqrtpricelimit", "slot0", "swap path"],
    "Cross-Chain":           ["cross-chain", "cross chain", "bridge message",
                               "layer 2 message", "ccip"],
    "ERC777":                ["erc777", "eip-777", "tokensreceived", "tokenssent"],
    "Governance":            ["governance", "proposal", "voting", "quorum",
                               "timelock", "snapshot"],
    "ERC1155":               ["erc1155", "eip-1155", "onerc1155received"],
    "ERC721":                ["erc721", "eip-721", "nft", "onerc721received",
                               "safemint"],
    "Gnosis safe":           ["gnosis", "safe wallet", "multisig guard"],
    "Opensea":               ["opensea", "seaport"],
    "EIP712":                ["eip-712", "eip712", "typed data", "ecrecover"],
    "Bridge":                ["asset bridge", "cross-chain bridge"],
    "Zksync":                ["zksync", "zk sync"],
    "Replay Attack":         ["replay attack", "replay protection"],
    "Solmate":               ["solmate"],
    "Compound":              ["compound finance", "ctoken", "comptroller"],
    "Solidity Version":      ["compiler version", "solidity version", "optimizer bug"],
    "EIP4494":               ["eip-4494", "eip4494"],
    "TWAP":                  ["twap", "time-weighted average", "observe("],
    "DAO":                   ["dao", "decentralized autonomous organization"],
}

_SUBTAG_ALIASES: dict[str, list[str]] = {
    "Violating CEI / Missing nonReentrant":  ["violating cei", "missing nonreentrant",
                                               "checks-effects-interactions"],
    "Asset Theft":                           ["asset theft", "steal funds",
                                               "unauthorized transfer", "drain funds"],
    "Invalid Validation":                    ["invalid validation", "missing validation",
                                               "missing check", "no check"],
    "State Update Inconsistency":            ["state update inconsistency",
                                               "inconsistent state", "stale state"],
    "Bad Condition":                         ["bad condition", "wrong condition",
                                               "incorrect condition"],
    "Implementation Error":                  ["implementation error",
                                               "incorrect implementation"],
    "Price Manipulation / Arbitrage opportunity": ["price manipulation", "arbitrage",
                                                    "price impact manipulation"],
    "Bypass Mechanism":                      ["bypass", "circumvent security",
                                               "evade check"],
    "Front Run":                             ["front-run", "frontrun", "sandwich",
                                               "front running"],
    "Precision Loss":                        ["precision loss", "truncation",
                                               "integer division truncat"],
    "Incorrect Formula":                     ["incorrect formula", "wrong formula",
                                               "calculation error"],
    "Missing Return Check":                  ["return value not checked",
                                               "unchecked return", "missing return check"],
    "Hardcoded Parameter":                   ["hardcoded", "hard-coded"],
    "Reward Manipulation":                   ["reward manipulation", "reward exploit"],
    "Not EIP Compliant":                     ["not eip compliant", "violates eip",
                                               "eip violation", "non-compliant"],
    "Missing minOut / maxAmount":            ["minout", "min out", "missing minimum output",
                                               "slippage parameter"],
    "Missing deadline":                      ["missing deadline", "no deadline"],
    "Inflation Attack":                      ["inflation attack", "share inflation",
                                               "first deposit exploit"],
    "Unsafe Downcast":                       ["unsafe downcast", "unsafe cast",
                                               "unsafe conversion"],
    "Storage Gap":                           ["storage gap", "storage collision"],
    "Nonce":                                 ["nonce", "replay nonce"],
    "Fee On Transfer Token":                 ["fee on transfer", "fee-on-transfer",
                                               "deflationary token"],
    "EVM Compatibility":                     ["evm compatibility", "evm difference",
                                               "push0 opcode"],
    "1/64 Gas Rule":                         ["1/64", "63/64", "eip-150 gas"],
    "Rounding Error":                        ["rounding error", "rounding direction"],
    "Stale Value":                           ["stale value", "stale price",
                                               "outdated data"],
    "Missing Time Constraint":               ["missing time constraint",
                                               "missing deadline", "no expiry"],
    "slot0":                                 ["slot0", "sqrtpricex96"],
    "Centralization Risk":                   ["centralization risk", "admin control",
                                               "single point of failure"],
    "Out of Gas":                            ["out of gas", "gas exhaustion",
                                               "unbounded loop"],
    "Duplicate Value":                       ["duplicate value", "duplicate key",
                                               "identifier collision"],
    "Missing Upper/Lower Bound Check":       ["missing bound check", "no upper bound",
                                               "no lower bound"],
    "Missing Initialization":               ["missing initialization", "uninitialized",
                                               "not initialized"],
    "Invariant Violation":                   ["invariant violation", "breaks invariant"],
    "No Recovery Mechanism":                 ["no recovery", "unrecoverable",
                                               "permanently locked"],
    "Cross-Function Reentrancy":             ["cross-function reentrancy"],
    "Refund Failed":                         ["refund failed", "refund revert"],
    "safeApprove":                           ["safeapprove", "safe approve deprecated"],
    "Rebase Token":                          ["rebase token", "rebasing token"],
    "Whale":                                 ["whale", "large holder"],
    "Missing Approval":                      ["missing approval", "missing approve",
                                               "transferfrom without approve"],
    "Execution Order Dependency":            ["execution order dependency",
                                               "ordering dependency"],
    "Misuse of Dependency":                  ["misuse of dependency",
                                               "incorrect library usage"],
    "Unauthorized Upgrade":                  ["unauthorized upgrade"],
    "Role Takeover":                         ["role takeover", "privilege escalation"],
    "Cannot Revoke":                         ["cannot revoke", "irrevocable"],
    "Missing Functionality":                 ["missing functionality", "not implemented"],
    "Diamond":                               ["diamond proxy", "eip-2535", "facet"],
    "Typo":                                  ["typographical error", "typo in code"],
    "Token Decimal":                         ["token decimal", "decimal mismatch"],
    "payable / receive()":                   ["payable function", "receive()"],
    "ERC777 Callback":                       ["erc777 callback", "tokensreceived hook"],
    "Case Sensitive":                        ["case sensitive", "case mismatch"],
    "Unfair Liquidation":                    ["unfair liquidation", "unjust liquidation"],
    "Cannot partial liquidations":           ["cannot partial liquidation",
                                               "partial liquidation not supported"],
    "Liquidation – Dust repay / front run evade liquidation":
                                             ["dust repay", "evade liquidation",
                                              "front run liquidation"],
    "No Incentive to Liquidate":             ["no incentive to liquidate",
                                              "liquidation incentive missing", "bad debt"],
    "onERC721Received callback":             ["onerc721received", "erc721 safe transfer callback"],
    "Arbitrary Add/Remove/Set/Call":         ["arbitrary call", "arbitrary set",
                                              "arbitrary add", "arbitrary remove"],
    "Scaling":                               ["scaling factor", "unit conversion",
                                              "denomination mismatch"],
    "Peg / Depeg":                           ["depeg", "peg loss", "broken peg"],
    "Does not match with Doc":               ["does not match", "deviates from spec",
                                              "contradicts natspec"],
    "Invalid Slippage Control / Missing slippage check":
                                             ["missing slippage check", "no slippage control"],
    "minOut set to 0":                       ["minout set to 0", "slippage set to zero"],
    "Block Time / Block Number":             ["block.timestamp", "block.number",
                                              "block time difference"],
}


def _build_keyword_index() -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for tag in TAGS:
        entries.append((tag.lower(), "tag", tag))
        for alias in _TAG_ALIASES.get(tag, []):
            entries.append((alias.lower(), "tag", tag))
    for subtag in SUBTAGS:
        entries.append((subtag.lower(), "subtag", subtag))
        for alias in _SUBTAG_ALIASES.get(subtag, []):
            entries.append((alias.lower(), "subtag", subtag))
    seen: set[tuple[str, str, str]] = set()
    unique = [e for e in entries if not (e in seen or seen.add(e))]  # type: ignore[func-returns-value]
    return sorted(unique, key=lambda x: len(x[0]), reverse=True)


_KW_INDEX = _build_keyword_index()


def match_taxonomy(text: str) -> tuple[set[str], set[str]]:
    """Return (matched_tags, matched_subtags) via keyword matching."""
    text_lower = text.lower()
    matched_tags:    set[str] = set()
    matched_subtags: set[str] = set()
    for kw, kind, name in _KW_INDEX:
        if kw in text_lower:
            if kind == "tag":
                matched_tags.add(name)
            else:
                matched_subtags.add(name)
    return matched_tags, matched_subtags


# ─────────────────────────────────────────────────────────────────────────────
# 5.  Main label builder
# ─────────────────────────────────────────────────────────────────────────────

def _iter_projects(base_dir: Path) -> Iterator[Path]:
    for p in sorted(base_dir.iterdir()):
        if p.is_dir() and not p.name.startswith("__") and not p.name.startswith("."):
            yield p


def build_labels(train_dir: Path = TRAIN_DIR) -> pd.DataFrame:
    """
    Extract per-finding labels for every project in train_dir.

    Returns DataFrame with columns:
        project_id, severity, tag, subtags, description
    One row per (project, finding, tag).
    """
    rows: list[dict] = []

    for proj_dir in _iter_projects(train_dir):
        project_id = proj_dir.name
        text = extract_audit_text(proj_dir)

        if not text.strip():
            print(f"[info] {project_id}: no audit text found")
            continue

        findings = split_findings(text)

        for finding in findings:
            search_text = finding["title"] + " " + finding["text"]
            f_tags, f_subtags = match_taxonomy(search_text)
            description = _extract_description(finding["title"], finding["text"])

            for tag in f_tags:
                valid = f_subtags & set(TAGS[tag]["subtags"])
                rows.append({
                    "project_id":  project_id,
                    "severity":    finding["severity"],
                    "tag":         tag,
                    "subtags":     sorted(valid),
                    "description": description,
                })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    print("Building labels for train split …")
    df = build_labels()
    print(df.head(20).to_string(index=False))
    print(f"\nTotal rows : {len(df)}")
    print(f"Projects   : {df.project_id.nunique()}")
    print(f"Unique tags: {df.tag.nunique()}")
    out = _ROOT / "dataset" / "train_labels.csv"
    df.to_csv(out, index=False)
    print(f"Saved → {out}")
