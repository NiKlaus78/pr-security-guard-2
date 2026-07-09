"""
LangGraph Pipeline Nodes

Each function is a node in the security scan graph.
Nodes receive the full state dict and return a partial update.

Nodes:
  1. regex_prefilter_node    — fast regex, no LLM
  2. llm_analyzer_node       — Claude Sonnet security analysis
  3. self_reflection_node    — Claude Sonnet self-critique loop
  4. gate_decision_node      — apply thresholds, set BLOCK/WARN/ALLOW
"""

import os
import re
import json
import uuid
import logging
from typing import Any

from langchain_mistralai import ChatMistralAI
from langchain_core.messages import SystemMessage, HumanMessage

from prompts.analyzer import ANALYZER_SYSTEM_PROMPT, build_analyzer_user_prompt
from prompts.critique import CRITIQUE_SYSTEM_PROMPT, build_critique_user_prompt
from tools.cve_checker import (
    extract_dependencies_from_diff,
    extract_dependencies_from_full_pom,
    check_dependencies_for_cves
)

log = logging.getLogger(__name__)

# Confidence thresholds
BLOCK_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.85"))
WARN_THRESHOLD = 0.60

# LLM setup — Mistral Codestral, code-specialist model
llm = ChatMistralAI(
    model="codestral-latest",
    max_tokens=8192,          # Increased — large diffs need more output tokens
    temperature=0,            # Deterministic for security analysis
    api_key=os.getenv("MISTRAL_API_KEY")
)


# ── Node 1: Regex Pre-filter ───────────────────────────────────────────────────

# Compiled patterns for speed — only match added lines (starting with +)
SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}'), "HARDCODED_PASSWORD", "CRITICAL"),
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'), "HARDCODED_API_KEY", "CRITICAL"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY", "CRITICAL"),
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}'), "AWS_SECRET_KEY", "CRITICAL"),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), "OPENAI_API_KEY", "CRITICAL"),
    (re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'), "PRIVATE_KEY", "CRITICAL"),
    (re.compile(r'(?i)(secret|token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'), "HARDCODED_SECRET", "HIGH"),
    (re.compile(r'jdbc:[a-z]+://[^:]+:[^@]+@'), "DB_CREDENTIALS_IN_URL", "CRITICAL"),
    (re.compile(r'(?i)ghp_[A-Za-z0-9]{36}'), "GITHUB_TOKEN", "CRITICAL"),
    (re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*'), "HARDCODED_JWT", "HIGH"),
]

CVV_LOG_PATTERN = re.compile(r'(?i)(log|print|console)\s*[\.\(].*?(cvv|card.?number|pan|ssn)', re.DOTALL)
SQL_INJECT_PATTERN = re.compile(r'(?i)(["\']\s*\+\s*\w+|string\.format\s*\(.*?select|"SELECT.*?" \+)', re.DOTALL)


def regex_prefilter_node(state: dict) -> dict:
    """
    Fast regex pre-filter. No LLM calls. Runs in milliseconds.
    Finds obvious secrets and flags them to inform the LLM analyzer.
    """
    log.info(f"[{state['scan_id']}] Node: regex_prefilter")

    diff = state["diff_content"]
    hits = []

    # Only scan added lines (lines starting with + but not +++)
    added_lines = []
    for i, line in enumerate(diff.split("\n"), 1):
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append((i, line[1:]))  # Strip leading +

    for line_num, line_content in added_lines:
        for pattern, finding_type, severity in SECRET_PATTERNS:
            if pattern.search(line_content):
                hits.append({
                    "type": finding_type,
                    "severity": severity,
                    "line_content": line_content.strip(),
                    "diff_line": line_num,
                    "source": "regex_prefilter"
                })
                break  # One hit per line is enough

        # Check CVV logging
        if CVV_LOG_PATTERN.search(line_content):
            hits.append({
                "type": "PCI_DATA_IN_LOGS",
                "severity": "HIGH",
                "line_content": line_content.strip(),
                "diff_line": line_num,
                "source": "regex_prefilter"
            })

    log.info(f"[{state['scan_id']}] Regex hits: {len(hits)}")
    return {"prefilter_hits": hits}


# ── Node 2: CVE Scanner ────────────────────────────────────────────────────────

def cve_scanner_node(state: dict) -> dict:
    """
    Scans pom.xml for Maven dependencies and queries OSV API for known CVEs.

    Uses the FULL pom.xml content (not just the diff) so that pre-existing
    vulnerable dependencies are also caught — not just newly added ones.
    """
    log.info(f"[{state['scan_id']}] Node: cve_scanner")

    diff = state["diff_content"]
    pom_xml_content = state.get("pom_xml_content", "")

    # Only run if pom.xml is in the diff
    if "pom.xml" not in diff:
        log.info(f"[{state['scan_id']}] No pom.xml in diff — skipping CVE scan")
        return {"cve_findings": []}

    # Extract actual pom.xml path from diff header (e.g. "webhook-service/pom.xml")
    pom_path = "pom.xml"
    for line in diff.split("\n"):
        if line.startswith("diff --git") and "pom.xml" in line:
            parts = line.split()
            for p in parts:
                if p.startswith("b/") and p.endswith("pom.xml"):
                    pom_path = p[2:]  # strip "b/"
                    break
            break
    log.info(f"[{state['scan_id']}] pom.xml path in repo: {pom_path}")

    # Prefer full pom.xml content over diff — catches ALL deps, not just new ones
    if pom_xml_content:
        log.info(
            f"[{state['scan_id']}] Using full pom.xml content "
            f"({len(pom_xml_content)} chars) — scanning ALL dependencies"
        )
        dependencies = extract_dependencies_from_full_pom(pom_xml_content)
    else:
        log.warning(
            f"[{state['scan_id']}] Full pom.xml not available — "
            f"falling back to diff-only"
        )
        dependencies = extract_dependencies_from_diff(diff)

    if not dependencies:
        log.info(f"[{state['scan_id']}] No dependencies found in pom.xml")
        return {"cve_findings": []}

    # Attach the real pom path to each dep so CVE findings show the correct file
    for dep in dependencies:
        dep["pom_path"] = pom_path

    log.info(f"[{state['scan_id']}] Checking {len(dependencies)} dependencies against OSV...")

    cve_findings = check_dependencies_for_cves(dependencies)

    log.info(
        f"[{state['scan_id']}] CVE scan complete | "
        f"dependencies_checked={len(dependencies)} cves_found={len(cve_findings)}"
    )

    return {"cve_findings": cve_findings}


# ── Node 3: LLM Security Analyzer ─────────────────────────────────────────────

def llm_analyzer_node(state: dict) -> dict:
    """
    Deep LLM semantic analysis using Mistral Codestral.
    Receives diff + prefilter hints + confirmed CVEs → returns structured findings JSON.
    """
    log.info(f"[{state['scan_id']}] Node: llm_analyzer")

    user_prompt = build_analyzer_user_prompt(
        diff_content=state["diff_content"],
        prefilter_hits=state["prefilter_hits"],
        cve_findings=state.get("cve_findings", []),
        pr_title=state["pr_title"],
        pr_author=state["pr_author"]
    )

    messages = [
        SystemMessage(content=ANALYZER_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]

    try:
        response = llm.invoke(messages)
        raw_text = response.content

        # Strip markdown fences — Codestral sometimes wraps output in ```json
        clean_json = raw_text.strip()
        if clean_json.startswith("```"):
            clean_json = re.sub(r"```(?:json)?\n?", "", clean_json).strip()
        if clean_json.endswith("```"):
            clean_json = clean_json[:-3].strip()

        # Handle case where model prepends prose before the array
        bracket_start = clean_json.find("[")
        if bracket_start > 0:
            log.warning(f"[{state['scan_id']}] Stripping prose before JSON array")
            clean_json = clean_json[bracket_start:]

        findings = json.loads(clean_json)

        # Ensure it's a list
        if isinstance(findings, dict):
            findings = findings.get("findings", [findings])

        log.info(f"[{state['scan_id']}] LLM raw findings: {len(findings)}")

        # Remove any LLM-hallucinated or duplicated CVE findings
        findings = [f for f in findings if f.get("type") != "VULN_DEPENDENCY"]

        # ── Regex-merge safety net ────────────────────────────────────────────
        # If Mistral returned fewer findings than regex hits, it under-reported.
        prefilter_hits = state.get("prefilter_hits", [])
        if len(findings) < len(prefilter_hits):
            log.warning(
                f"[{state['scan_id']}] Mistral returned {len(findings)} findings "
                f"but regex found {len(prefilter_hits)} hits — merging missing ones"
            )
            findings = _merge_regex_into_findings(findings, prefilter_hits)
            log.info(f"[{state['scan_id']}] After regex merge: {len(findings)} findings")

        # ── CVE merge ────────────────────────────────────────────────────────
        # Always inject confirmed OSV CVE findings — these are facts, not LLM guesses.
        # The LLM may have already mentioned them, so we deduplicate by pom.xml line.
        cve_findings = state.get("cve_findings", [])
        if cve_findings:
            findings = _merge_cve_into_findings(findings, cve_findings)
            log.info(f"[{state['scan_id']}] After CVE merge: {len(findings)} findings")

        return {"raw_findings": findings}

    except json.JSONDecodeError as e:
        log.error(f"[{state['scan_id']}] JSON parse failed: {e}\nRaw: {raw_text[:500]}")
        # Full fallback — convert all regex hits to findings
        return {"raw_findings": _prefilter_to_findings(state["prefilter_hits"])}

    except Exception as e:
        log.error(f"[{state['scan_id']}] LLM analyzer failed: {e}")
        return {"raw_findings": _prefilter_to_findings(state.get("prefilter_hits", [])),
                "errors": state.get("errors", []) + [str(e)]}


# ── Node 3: Self-Reflection Critique ──────────────────────────────────────────

def self_reflection_node(state: dict) -> dict:
    """
    The self-critique loop — Claude Sonnet reviews its own findings
    and adjusts confidence scores to minimize false positives.
    """
    log.info(f"[{state['scan_id']}] Node: self_reflection")

    try:
        raw_findings = state["raw_findings"]
        if not raw_findings:
            log.info(f"[{state['scan_id']}] No findings to critique.")
            return {"critiqued_findings": []}

        # Filter out ground-truth CVE findings from the ones we send to LLM for critique
        findings_to_critique = [f for f in raw_findings if f.get("type") != "VULN_DEPENDENCY"]

        critique_map = {}
        if findings_to_critique:
            log.info(f"[{state['scan_id']}] Critiquing {len(findings_to_critique)} non-CVE findings...")
            user_prompt = build_critique_user_prompt(
                findings=findings_to_critique,
                diff_content=state["diff_content"]
            )

            messages = [
                SystemMessage(content=CRITIQUE_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt)
            ]

            try:
                response = llm.invoke(messages)
                raw_text = response.content

                clean_json = raw_text.strip()
                if clean_json.startswith("```"):
                    clean_json = re.sub(r"```(?:json)?\n?", "", clean_json).strip()

                critiques = json.loads(clean_json)
                critique_map = {c["finding_id"]: c for c in critiques}
            except Exception as e:
                log.error(f"[{state['scan_id']}] Self-reflection LLM call failed: {e}")
        else:
            log.info(f"[{state['scan_id']}] No non-CVE findings to critique. Skipping critique LLM.")

        critiqued = []
        for finding in raw_findings:
            fid = finding.get("finding_id", str(uuid.uuid4())[:8])
            finding["finding_id"] = fid

            if finding.get("type") == "VULN_DEPENDENCY":
                # CVE findings are database facts — auto-confirm and preserve their high confidence
                critiqued.append({
                    **finding,
                    "initial_confidence": finding.get("confidence", 0.97),
                    "final_confidence": finding.get("confidence", 0.97),
                    "critique_verdict": "CONFIRMED",
                    "critique_rationale": "Factual CVE finding from OSV database — skipped critique."
                })
            else:
                critique = critique_map.get(fid, {})
                initial_confidence = finding.get("confidence", 0.7)
                adjustment = critique.get("confidence_adjustment", 0.0)
                final_confidence = max(0.0, min(1.0, initial_confidence + adjustment))

                critiqued.append({
                    **finding,
                    "initial_confidence": initial_confidence,
                    "final_confidence": final_confidence,
                    "critique_verdict": critique.get("verdict", "CONFIRMED"),
                    "critique_rationale": critique.get("rationale", "No critique provided.")
                })

        false_positives = sum(1 for f in critiqued if f["critique_verdict"] == "FALSE_POSITIVE")
        log.info(
            f"[{state['scan_id']}] Critique complete | "
            f"findings={len(critiqued)} false_positives={false_positives}"
        )
        return {"critiqued_findings": critiqued}

    except Exception as e:
        log.error(f"[{state['scan_id']}] Self-reflection failed: {e}")
        # If critique fails, pass raw findings through unchanged
        return {
            "critiqued_findings": raw_findings,
            "errors": state.get("errors", []) + [f"critique_failed: {str(e)}"]
        }


# ── Node 4: Gate Decision ──────────────────────────────────────────────────────

def gate_decision_node(state: dict) -> dict:
    """
    Applies confidence thresholds to determine gate action per finding
    and the overall merge decision.

    Threshold logic:
      final_confidence >= 0.85 AND verdict != FALSE_POSITIVE → BLOCK (if CRITICAL/HIGH)
      final_confidence >= 0.60 AND verdict != FALSE_POSITIVE → WARN
      else                                                   → DISCARD
    """
    log.info(f"[{state['scan_id']}] Node: gate_decision")

    critiqued = state["critiqued_findings"]
    final_findings = []
    has_block = False
    has_warn = False

    for finding in critiqued:
        confidence = finding.get("final_confidence", 0.0)
        verdict = finding.get("critique_verdict", "CONFIRMED")
        severity = finding.get("severity", "MEDIUM")

        if verdict == "FALSE_POSITIVE":
            gate_action = "DISCARD"
        elif confidence >= BLOCK_THRESHOLD and severity in ("CRITICAL", "HIGH"):
            gate_action = "BLOCK"
            has_block = True
        elif confidence >= WARN_THRESHOLD:
            gate_action = "WARN"
            has_warn = True
        else:
            gate_action = "DISCARD"

        final_findings.append({**finding, "gate_action": gate_action})

    # Overall decision
    if has_block:
        gate_decision = "BLOCK"
    elif has_warn:
        gate_decision = "WARN"
    else:
        gate_decision = "ALLOW"

    blocked = sum(1 for f in final_findings if f["gate_action"] == "BLOCK")
    warned = sum(1 for f in final_findings if f["gate_action"] == "WARN")
    discarded = sum(1 for f in final_findings if f["gate_action"] == "DISCARD")

    log.info(
        f"[{state['scan_id']}] Gate decision: {gate_decision} | "
        f"block={blocked} warn={warned} discard={discarded}"
    )

    return {
        "final_findings": final_findings,
        "gate_decision": gate_decision
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _merge_cve_into_findings(llm_findings: list, cve_findings: list) -> list:
    """
    Merges confirmed OSV CVE findings into the LLM findings list.
    Deduplicates by checking if the LLM already mentioned the same
    dependency (by artifact name or pom.xml line number).
    CVE findings have 0.98 confidence — they are database facts, not guesses.
    """
    merged = list(llm_findings)

    # Build set of already-covered pom.xml lines and artifact names
    existing_lines = {f.get("line", -1) for f in llm_findings if f.get("file") == "pom.xml"}
    existing_evidence_lower = {
        f.get("evidence", "").lower() for f in llm_findings
    }

    for cve in cve_findings:
        cve_line = cve.get("line", -1)
        artifact = cve.get("cve_id", "").lower()

        already_covered = (
            cve_line in existing_lines or
            any(artifact in ev for ev in existing_evidence_lower if ev)
        )

        if not already_covered:
            log.info(f"Injecting CVE finding: {cve['cve_id']} CVSS={cve.get('cvss_score', '?')}")
            merged.append(cve)

    return merged


def _merge_regex_into_findings(llm_findings: list, prefilter_hits: list) -> list:
    """
    Merges regex prefilter hits into LLM findings.
    Only adds hits that aren't already represented in LLM findings
    (matched by line number or evidence content similarity).
    Ensures we never lose a confirmed regex detection due to LLM under-reporting.
    """
    merged = list(llm_findings)

    # Build a set of evidence strings already in LLM findings (lowercased for fuzzy match)
    existing_evidence = {
        f.get("evidence", "").lower()[:80]
        for f in llm_findings
    }
    existing_lines = {f.get("line", -1) for f in llm_findings}

    for i, hit in enumerate(prefilter_hits):
        line_content_lower = hit["line_content"].lower()[:80]
        diff_line = hit.get("diff_line", 0)

        # Skip if already captured by LLM (same line or very similar evidence)
        already_covered = (
            diff_line in existing_lines or
            any(line_content_lower in ev or ev in line_content_lower
                for ev in existing_evidence if len(ev) > 10)
        )

        if not already_covered:
            merged.append({
                "finding_id": f"regex_{i:03d}",
                "severity": hit["severity"],
                "type": hit["type"],
                "file": "unknown",
                "line": diff_line,
                "evidence": hit["line_content"][:200],
                "confidence": 0.88,   # High confidence — regex pattern confirmed
                "policy_ref": "SEC-001",
                "remediation": "Move to environment variables or a secrets manager (e.g. AWS Secrets Manager, Vault)."
            })

    return merged


def _prefilter_to_findings(hits: list) -> list:
    """Convert regex prefilter hits to finding format as fallback."""
    findings = []
    for i, hit in enumerate(hits):
        findings.append({
            "finding_id": f"regex_{i:03d}",
            "severity": hit["severity"],
            "type": hit["type"],
            "file": "unknown",
            "line": 0,
            "evidence": hit["line_content"][:200],
            "confidence": 0.75,
            "policy_ref": "SEC-001",
            "remediation": "Move to environment variables or secrets manager."
        })
    return findings


# Alias — keeps backward compatibility if graph.py uses old name
dependency_scanner_node = cve_scanner_node
