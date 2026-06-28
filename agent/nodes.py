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
from tools.cve_checker import scan_diff_for_vulnerabilities, vulnerability_to_finding

log = logging.getLogger(__name__)

# Confidence thresholds
BLOCK_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.85"))
WARN_THRESHOLD = 0.60

# LLM setup — Mistral Codestral, code-specialist model
llm = ChatMistralAI(
    model="codestral-latest",
    max_tokens=4096,
    temperature=0,           # Deterministic for security analysis
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


# ── Node 2: Dependency Scanner ─────────────────────────────────────────────────

# Default CVSS threshold from security policy
DEFAULT_MIN_CVSS = float(os.getenv("MIN_CVSS_TO_FLAG", "7.0"))


def dependency_scanner_node(state: dict) -> dict:
    """
    Scans dependency file changes in the diff for known vulnerabilities
    using the OSV.dev API. This provides factual CVE data to the LLM
    analyzer instead of relying on the model's training-data knowledge.

    Supports: Maven (pom.xml), PyPI (requirements.txt), npm (package.json),
              Go (go.mod), Gradle (build.gradle), Cargo (Cargo.toml)
    """
    log.info(f"[{state['scan_id']}] Node: dependency_scanner")

    diff = state["diff_content"]

    try:
        parsed_deps, vulns = scan_diff_for_vulnerabilities(diff, DEFAULT_MIN_CVSS)

        # Convert vulnerabilities to standard finding format
        dep_findings = [vulnerability_to_finding(v) for v in vulns]

        log.info(
            f"[{state['scan_id']}] Dependency scan: "
            f"parsed={len(parsed_deps)} deps, "
            f"vulnerabilities={len(dep_findings)}"
        )
        return {"dep_scan_findings": dep_findings}

    except Exception as e:
        log.error(f"[{state['scan_id']}] Dependency scanner failed: {e}")
        return {
            "dep_scan_findings": [],
            "errors": state.get("errors", []) + [f"dep_scanner_failed: {str(e)}"]
        }


# ── Node 3: LLM Security Analyzer ─────────────────────────────────────────────

def llm_analyzer_node(state: dict) -> dict:
    """
    Deep LLM semantic analysis using Mistral Codestral.
    Receives the diff + prefilter hints + dependency CVE data
    → returns structured findings JSON.
    """
    log.info(f"[{state['scan_id']}] Node: llm_analyzer")

    dep_scan_findings = state.get("dep_scan_findings", [])

    user_prompt = build_analyzer_user_prompt(
        diff_content=state["diff_content"],
        prefilter_hits=state["prefilter_hits"],
        pr_title=state["pr_title"],
        pr_author=state["pr_author"],
        dep_scan_findings=dep_scan_findings
    )

    messages = [
        SystemMessage(content=ANALYZER_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]

    try:
        response = llm.invoke(messages)
        raw_text = response.content

        # Parse JSON response — strip any markdown fences if model added them
        clean_json = raw_text.strip()
        if clean_json.startswith("```"):
            clean_json = re.sub(r"```(?:json)?\n?", "", clean_json).strip()

        findings = json.loads(clean_json)

        # Ensure it's a list
        if isinstance(findings, dict):
            findings = findings.get("findings", [findings])

        # Merge in dependency scan findings (OSV-confirmed CVEs)
        # These are factual and should not be duplicated by the LLM
        existing_cves = {f.get("cve_id") for f in findings if f.get("cve_id")}
        for dep_finding in dep_scan_findings:
            if dep_finding.get("cve_id") not in existing_cves:
                findings.append(dep_finding)

        log.info(f"[{state['scan_id']}] LLM raw findings: {len(findings)} "
                 f"(includes {len(dep_scan_findings)} from dep scanner)")
        return {"raw_findings": findings}

    except json.JSONDecodeError as e:
        log.error(f"[{state['scan_id']}] JSON parse failed: {e}\nRaw: {raw_text[:500]}")
        # Fall back to prefilter hits + dep findings
        fallback = _prefilter_to_findings(state["prefilter_hits"])
        fallback.extend(dep_scan_findings)
        return {"raw_findings": fallback}

    except Exception as e:
        log.error(f"[{state['scan_id']}] LLM analyzer failed: {e}")
        # Even if LLM fails, still return dependency findings
        return {
            "raw_findings": dep_scan_findings,
            "errors": state.get("errors", []) + [str(e)]
        }


# ── Node 4: Self-Reflection Critique ──────────────────────────────────────────

def self_reflection_node(state: dict) -> dict:
    """
    The self-critique loop — Claude Sonnet reviews its own findings
    and adjusts confidence scores to minimize false positives.
    """
    log.info(f"[{state['scan_id']}] Node: self_reflection")

    raw_findings = state["raw_findings"]
    if not raw_findings:
        log.info(f"[{state['scan_id']}] No findings to critique.")
        return {"critiqued_findings": []}

    user_prompt = build_critique_user_prompt(
        findings=raw_findings,
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

        # Merge critique results back into findings
        critique_map = {c["finding_id"]: c for c in critiques}

        critiqued = []
        for finding in raw_findings:
            fid = finding.get("finding_id", str(uuid.uuid4())[:8])
            finding["finding_id"] = fid

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


# ── Node 5: Gate Decision ──────────────────────────────────────────────────────

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
