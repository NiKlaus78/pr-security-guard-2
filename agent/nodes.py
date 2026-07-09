"""
LangGraph Pipeline Nodes

Each function is a node in the security scan graph.
Nodes receive the full state dict and return a partial update.

Nodes:
  1. regex_prefilter_node    — fast regex, no LLM (language agnostic)
  2. cve_scanner_node        — Maven / npm / PyPI dependency CVE scanning
  3. llm_analyzer_node       — Mistral Codestral security analysis
  4. self_reflection_node    — Mistral self-critique loop
  5. gate_decision_node      — apply thresholds, set BLOCK/WARN/ALLOW
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
    extract_dependencies_from_package_json,
    extract_dependencies_from_requirements_txt,
    check_dependencies_for_cves,
)

log = logging.getLogger(__name__)

BLOCK_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.85"))
WARN_THRESHOLD = 0.60

llm = ChatMistralAI(
    model="codestral-latest",
    max_tokens=8192,
    temperature=0,
    api_key=os.getenv("MISTRAL_API_KEY")
)


# ── Node 1: Regex Pre-filter ───────────────────────────────────────────────────
# Language-agnostic — secrets look the same whether in Java, JS, or Python.

SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}'), "HARDCODED_PASSWORD", "CRITICAL"),
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'), "HARDCODED_API_KEY", "CRITICAL"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY", "CRITICAL"),
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}'), "AWS_SECRET_KEY", "CRITICAL"),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), "API_KEY_PATTERN", "CRITICAL"),
    (re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'), "PRIVATE_KEY", "CRITICAL"),
    (re.compile(r'(?i)(secret|token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'), "HARDCODED_SECRET", "HIGH"),
    (re.compile(r'(?i)(jdbc|mongodb|postgres|mysql)://[^:]+:[^@]+@'), "DB_CREDENTIALS_IN_URL", "CRITICAL"),
    (re.compile(r'(?i)ghp_[A-Za-z0-9]{36}'), "GITHUB_TOKEN", "CRITICAL"),
    (re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*'), "HARDCODED_JWT", "HIGH"),
]

# ── Dangerous function call patterns ────────────────────────────────────────
# LLM-only findings (SQL injection, eval, deserialization) have no database
# safety net like CVEs do — Mistral under-reports these inconsistently.
# This regex floor guarantees well-known dangerous one-liners are always
# caught, language-agnostic (Java, JavaScript, Python).

DANGEROUS_CALL_PATTERNS = [
    (re.compile(r'(?i)\beval\s*\('), "EVAL_INJECTION", "HIGH"),
    (re.compile(r'(?i)\bexec\s*\('), "EVAL_INJECTION", "HIGH"),
    (re.compile(r'(?i)pickle\.loads?\s*\('), "INSECURE_DESERIALIZE", "HIGH"),
    (re.compile(r'(?i)subprocess\.(run|call|popen|check_output)\s*\([^)]*shell\s*=\s*True'), "COMMAND_INJECTION", "HIGH"),
    (re.compile(r'(?i)\bos\.system\s*\('), "COMMAND_INJECTION", "HIGH"),
    (re.compile(r'(?i)(child_process\.)?exec(Sync)?\s*\([^)]*\+'), "COMMAND_INJECTION", "HIGH"),
    (re.compile(r'(?i)jwt\.decode\s*\('), "BROKEN_AUTH", "HIGH"),
    (re.compile(r'(?i)yaml\.load\s*\('), "INSECURE_DESERIALIZE", "MEDIUM"),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('), "COMMAND_INJECTION", "HIGH"),
    (re.compile(r'new\s+ObjectInputStream\s*\('), "INSECURE_DESERIALIZE", "HIGH"),
    (re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\'][^"\']*["\']?\s*\+\s*\w+'), "SQL_INJECTION", "HIGH"),
    (re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\b.*[\'"]\s*%\s*\w+'), "SQL_INJECTION", "HIGH"),
    (re.compile(r'(?i)f["\'][^"\']*?(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\{[^}]+\}'), "SQL_INJECTION", "HIGH"),
    (re.compile(r'(?i)res\.(send|write)\s*\([^)]*req\.(query|body|params)'), "XSS_RISK", "MEDIUM"),
]

CVV_LOG_PATTERN = re.compile(r'(?i)(log|print|console)\s*[\.\(].*?(cvv|card.?number|pan|ssn)', re.DOTALL)


def regex_prefilter_node(state: dict) -> dict:
    """Fast regex pre-filter. No LLM calls. Language-agnostic."""
    log.info(f"[{state['scan_id']}] Node: regex_prefilter")

    diff = state["diff_content"]
    hits = []

    added_lines = []
    current_file = "unknown"
    for i, line in enumerate(diff.split("\n"), 1):
        if line.startswith("diff --git"):
            # Extract "b/path/to/file.ext" -> "path/to/file.ext"
            parts = line.split(" ")
            for p in parts:
                if p.startswith("b/"):
                    current_file = p[2:]
                    break
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append((i, line[1:], current_file))

    for line_num, line_content, file_path in added_lines:
        for pattern, finding_type, severity in SECRET_PATTERNS:
            if pattern.search(line_content):
                hits.append({
                    "type": finding_type,
                    "severity": severity,
                    "line_content": line_content.strip(),
                    "diff_line": line_num,
                    "file": file_path,
                    "source": "regex_prefilter"
                })
                break

        for pattern, finding_type, severity in DANGEROUS_CALL_PATTERNS:
            if pattern.search(line_content):
                hits.append({
                    "type": finding_type,
                    "severity": severity,
                    "line_content": line_content.strip(),
                    "diff_line": line_num,
                    "file": file_path,
                    "source": "regex_dangerous_call"
                })
                break

        if CVV_LOG_PATTERN.search(line_content):
            hits.append({
                "type": "PCI_DATA_IN_LOGS",
                "severity": "HIGH",
                "line_content": line_content.strip(),
                "diff_line": line_num,
                "file": file_path,
                "source": "regex_prefilter"
            })

    log.info(f"[{state['scan_id']}] Regex hits: {len(hits)}")
    return {"prefilter_hits": hits}


# ── Node 2: CVE Scanner — Multi-Language ───────────────────────────────────────

def cve_scanner_node(state: dict) -> dict:
    """
    Scans dependency manifest files for known CVEs via OSV API.
    Supports three ecosystems detected from the diff:
      pom.xml          → Maven  (Java)
      package.json     → npm    (JavaScript / Node.js)
      requirements.txt → PyPI   (Python)

    Uses the FULL manifest content (not just the diff) so pre-existing
    vulnerable dependencies are caught, not just newly added ones.
    """
    log.info(f"[{state['scan_id']}] Node: cve_scanner")

    diff = state["diff_content"]
    all_dependencies = []

    # ── Maven: pom.xml ──────────────────────────────────────────────────────
    pom_xml_content = state.get("pom_xml_content", "")
    if "pom.xml" in diff:
        pom_path = _extract_manifest_path(diff, "pom.xml")
        log.info(f"[{state['scan_id']}] pom.xml detected at '{pom_path}'")
        if pom_xml_content:
            deps = extract_dependencies_from_full_pom(pom_xml_content)
        else:
            log.warning(f"[{state['scan_id']}] Full pom.xml unavailable — using diff fallback")
            deps = extract_dependencies_from_diff(diff)
        for d in deps:
            d["manifest_path"] = pom_path
        all_dependencies.extend(deps)

    # ── npm: package.json ───────────────────────────────────────────────────
    package_json_content = state.get("package_json_content", "")
    if "package.json" in diff:
        pkg_path = _extract_manifest_path(diff, "package.json")
        log.info(f"[{state['scan_id']}] package.json detected at '{pkg_path}'")
        if package_json_content:
            deps = extract_dependencies_from_package_json(package_json_content)
            for d in deps:
                d["manifest_path"] = pkg_path
            all_dependencies.extend(deps)
        else:
            log.warning(f"[{state['scan_id']}] Full package.json unavailable — skipping npm CVE scan")

    # ── PyPI: requirements.txt ──────────────────────────────────────────────
    requirements_content = state.get("requirements_txt_content", "")
    if "requirements.txt" in diff:
        req_path = _extract_manifest_path(diff, "requirements.txt")
        log.info(f"[{state['scan_id']}] requirements.txt detected at '{req_path}'")
        if requirements_content:
            deps = extract_dependencies_from_requirements_txt(requirements_content)
            for d in deps:
                d["manifest_path"] = req_path
            all_dependencies.extend(deps)
        else:
            log.warning(f"[{state['scan_id']}] Full requirements.txt unavailable — skipping PyPI CVE scan")

    if not all_dependencies:
        log.info(f"[{state['scan_id']}] No dependency manifests found in diff — skipping CVE scan")
        return {"cve_findings": []}

    log.info(
        f"[{state['scan_id']}] Checking {len(all_dependencies)} dependencies "
        f"across {len({d.get('ecosystem') for d in all_dependencies})} ecosystem(s) against OSV..."
    )

    cve_findings = check_dependencies_for_cves(all_dependencies)

    log.info(
        f"[{state['scan_id']}] CVE scan complete | "
        f"dependencies_checked={len(all_dependencies)} cves_found={len(cve_findings)}"
    )

    return {"cve_findings": cve_findings}


def _extract_manifest_path(diff_content: str, filename: str) -> str:
    """
    Extracts the actual repo-relative path of a manifest file from the diff header.
    Handles monorepo layouts e.g. "backend/package.json" not just "package.json".
    """
    for line in diff_content.split("\n"):
        if line.startswith("diff --git") and filename in line:
            parts = line.split()
            for p in parts:
                if p.startswith("b/") and p.endswith(filename):
                    return p[2:]
    return filename


# ── Node 3: LLM Security Analyzer ─────────────────────────────────────────────

def llm_analyzer_node(state: dict) -> dict:
    """
    Deep LLM semantic analysis using Mistral Codestral.
    Language-agnostic prompt — works across Java, JavaScript, Python, etc.
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

        clean_json = raw_text.strip()
        if clean_json.startswith("```"):
            clean_json = re.sub(r"```(?:json)?\n?", "", clean_json).strip()
        if clean_json.endswith("```"):
            clean_json = clean_json[:-3].strip()

        bracket_start = clean_json.find("[")
        if bracket_start > 0:
            log.warning(f"[{state['scan_id']}] Stripping prose before JSON array")
            clean_json = clean_json[bracket_start:]

        findings = json.loads(clean_json)

        if isinstance(findings, dict):
            findings = findings.get("findings", [findings])

        log.info(f"[{state['scan_id']}] LLM raw findings: {len(findings)}")

        prefilter_hits = state.get("prefilter_hits", [])
        if len(findings) < len(prefilter_hits):
            log.warning(
                f"[{state['scan_id']}] Mistral returned {len(findings)} findings "
                f"but regex found {len(prefilter_hits)} hits — merging missing ones"
            )
            findings = _merge_regex_into_findings(findings, prefilter_hits)
            log.info(f"[{state['scan_id']}] After regex merge: {len(findings)} findings")

        cve_findings = state.get("cve_findings", [])
        if cve_findings:
            findings = _merge_cve_into_findings(findings, cve_findings)
            log.info(f"[{state['scan_id']}] After CVE merge: {len(findings)} findings")

        return {"raw_findings": findings}

    except json.JSONDecodeError as e:
        log.error(f"[{state['scan_id']}] JSON parse failed: {e}\nRaw: {raw_text[:500]}")
        merged = _merge_cve_into_findings(
            _prefilter_to_findings(state["prefilter_hits"]),
            state.get("cve_findings", [])
        )
        return {"raw_findings": merged}

    except Exception as e:
        log.error(f"[{state['scan_id']}] LLM analyzer failed: {e}")
        merged = _merge_cve_into_findings(
            _prefilter_to_findings(state.get("prefilter_hits", [])),
            state.get("cve_findings", [])
        )
        return {"raw_findings": merged, "errors": state.get("errors", []) + [str(e)]}


# ── Node 4: Self-Reflection Critique ──────────────────────────────────────────

def self_reflection_node(state: dict) -> dict:
    """Self-critique loop — reviews findings to eliminate false positives."""
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
        return {
            "critiqued_findings": raw_findings,
            "errors": state.get("errors", []) + [f"critique_failed: {str(e)}"]
        }


# ── Node 5: Gate Decision ──────────────────────────────────────────────────────

def gate_decision_node(state: dict) -> dict:
    """Applies confidence thresholds to determine gate action and merge decision."""
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
    """Merges confirmed OSV CVE findings into LLM findings, deduplicated."""
    merged = list(llm_findings)

    existing_evidence_lower = {f.get("evidence", "").lower() for f in llm_findings}

    for cve in cve_findings:
        artifact = cve.get("cve_id", "").lower()
        already_covered = any(artifact in ev for ev in existing_evidence_lower if ev)
        if not already_covered:
            log.info(f"Injecting CVE finding: {cve.get('cve_id')} CVSS={cve.get('cvss_score', '?')}")
            merged.append(cve)

    return merged


def _merge_regex_into_findings(llm_findings: list, prefilter_hits: list) -> list:
    """Merges regex prefilter hits not already captured by the LLM."""
    merged = list(llm_findings)

    existing_evidence = {f.get("evidence", "").lower()[:80] for f in llm_findings}
    existing_lines = {f.get("line", -1) for f in llm_findings}

    severity_confidence = {
        "CRITICAL": 0.93,
        "HIGH": 0.88,
        "MEDIUM": 0.70,
        "LOW": 0.50,
    }

    for i, hit in enumerate(prefilter_hits):
        line_content_lower = hit["line_content"].lower()[:80]
        diff_line = hit.get("diff_line", 0)

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
                "file": hit.get("file", "unknown"),
                "line": diff_line,
                "evidence": hit["line_content"][:200],
                "confidence": severity_confidence.get(hit["severity"], 0.75),
                "policy_ref": "SEC-001",
                "remediation": "Move to environment variables or a secrets manager."
            })

    return merged


def _prefilter_to_findings(hits: list) -> list:
    """Convert regex prefilter hits to finding format as fallback."""
    severity_confidence = {
        "CRITICAL": 0.92,
        "HIGH": 0.80,
        "MEDIUM": 0.65,
        "LOW": 0.50,
    }
    findings = []
    for i, hit in enumerate(hits):
        severity = hit["severity"]
        findings.append({
            "finding_id": f"regex_{i:03d}",
            "severity": severity,
            "type": hit["type"],
            "file": hit.get("file", "unknown"),
            "line": hit.get("diff_line", 0),
            "evidence": hit["line_content"][:200],
            "confidence": severity_confidence.get(severity, 0.75),
            "policy_ref": "SEC-001",
            "remediation": "Move to environment variables or secrets manager."
        })
    return findings


# Alias — backward compatibility with older graph.py versions
dependency_scanner_node = cve_scanner_node