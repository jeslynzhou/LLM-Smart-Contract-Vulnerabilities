"""
label_extractor.py — extract vulnerability labels from train audit artefacts.

Pipeline per project:
  1. Collect audit text  (PDFs → pdfplumber, markdown/txt → read directly)
  2. Split into individual findings
  3. Match each finding to taxonomy tags + subtags via keyword index
  4. Aggregate → one row per (project_id, tag, subtags)

Main entry point:
    from src.label_extractor import build_labels
    df = build_labels(TRAIN_DIR)   # returns a DataFrame
"""

from __future__ import annotations

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
# PDFs: cover both 'audits/' and 'audit/' (with/without s), any depth
_PDF_GLOBS = ["audit/**/*.pdf", "audits/**/*.pdf"]

# Markdown: only real audit/report files, not GitHub issue templates
_MD_GLOBS  = [
    "bot-report.md",
    "4naly3er-report.md",
    "slither/**/*.md",
]


_SKIP_DIRS  = {"lib", "node_modules", "__MACOSX", ".git", "ISSUE_TEMPLATE"}
# Filenames that look like audit artefacts but are not
_SKIP_NAMES = {".github", "bug_report.md", "audit-item.md"}


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Text extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_pdf(path: Path) -> str:
    """Extract text from a PDF using pdfplumber (pip install pdfplumber)."""
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


def _collect_audit_files(project_dir: Path) -> list[Path]:
    seen: set[Path] = set()
    results: list[Path] = []

    # PDFs and named markdown files via glob
    for pattern in _PDF_GLOBS + _MD_GLOBS:
        for p in project_dir.glob(pattern):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.name in _SKIP_NAMES:
                continue
            if p not in seen:
                seen.add(p)
                results.append(p)

    # Discord exports: use iterdir, not glob — discord filenames contain [ ]
    # which Python's glob treats as character-class syntax and won't match.
    discord_dir = project_dir / "discord-export"
    if discord_dir.is_dir():
        for p in discord_dir.iterdir():
            if p.suffix == ".txt" and p not in seen:
                seen.add(p)
                results.append(p)

    return results


def extract_audit_text(project_dir: Path) -> str:
    """Return all audit text for a project concatenated."""
    parts: list[str] = []
    for f in _collect_audit_files(project_dir):
        if f.suffix == ".pdf":
            parts.append(_extract_pdf(f))
        else:
            parts.append(_extract_md(f))
    return "\n\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# 2.  Finding extraction
# ─────────────────────────────────────────────────────────────────────────────

def split_findings(text: str) -> list[str]:
    """
    Split audit text into individual finding blocks on headings like:
      ## [H-01] Title,  ## M-02: Title,  ### L-03 - Title
    Falls back to the full text as one block if no headings are found.
    """
    pattern = re.compile(
        r"\n(?=#+\s*(?:\[?[HMLCGNI]-\d+\]?|\*\*[HMLCGNI]-\d+\*\*))",
        re.IGNORECASE,
    )
    blocks = pattern.split(text)
    blocks = [b.strip() for b in blocks if b.strip()]
    return blocks if blocks else [text]


# ─────────────────────────────────────────────────────────────────────────────
# 3.  Keyword index + matching
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
    """
    Returns sorted list of (keyword_lower, kind, canonical_name)
    sorted by keyword length descending so longer phrases match first.
    """
    entries: list[tuple[str, str, str]] = []

    for tag in TAGS:
        entries.append((tag.lower(), "tag", tag))
        for alias in _TAG_ALIASES.get(tag, []):
            entries.append((alias.lower(), "tag", tag))

    for subtag in SUBTAGS:
        entries.append((subtag.lower(), "subtag", subtag))
        for alias in _SUBTAG_ALIASES.get(subtag, []):
            entries.append((alias.lower(), "subtag", subtag))

    # deduplicate, longest first
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
# 4.  Main label builder
# ─────────────────────────────────────────────────────────────────────────────

def _iter_projects(base_dir: Path) -> Iterator[Path]:
    for p in sorted(base_dir.iterdir()):
        if p.is_dir() and not p.name.startswith("__") and not p.name.startswith("."):
            yield p


def build_labels(
    train_dir: Path = TRAIN_DIR,
    *,
    per_finding: bool = False,
) -> pd.DataFrame:
    """
    Extract labels for every project in train_dir.

    Args:
        train_dir:   Path to the train split directory.
        per_finding: If True, return one row per finding block.
                     If False (default), aggregate to one row per
                     (project_id, tag) with matched subtags as a list.

    Returns:
        DataFrame with columns:
            project_id, tag, subtags            (per_finding=False)
            project_id, finding_idx, tag, subtags  (per_finding=True)
    """
    rows: list[dict] = []

    for proj_dir in _iter_projects(train_dir):
        project_id = proj_dir.name
        text = extract_audit_text(proj_dir)

        if not text.strip():
            print(f"[info] {project_id}: no audit text found")
            continue

        findings = split_findings(text)
        proj_tags: dict[str, set[str]] = {}  # tag -> set of matched subtags

        for idx, finding in enumerate(findings):
            f_tags, f_subtags = match_taxonomy(finding)

            if per_finding:
                for tag in f_tags:
                    # only keep subtags the taxonomy says belong to this tag
                    valid = f_subtags & set(TAGS[tag]["subtags"])
                    rows.append({
                        "project_id":  project_id,
                        "finding_idx": idx,
                        "tag":         tag,
                        "subtags":     sorted(valid),
                    })
            else:
                for tag in f_tags:
                    valid = f_subtags & set(TAGS[tag]["subtags"])
                    proj_tags.setdefault(tag, set()).update(valid)

        if not per_finding:
            for tag, subtags in proj_tags.items():
                rows.append({
                    "project_id": project_id,
                    "tag":        tag,
                    "subtags":    sorted(subtags),
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
