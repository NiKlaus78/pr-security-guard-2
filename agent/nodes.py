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
    extract_dependencies_from_package_json,
    extract_dependencies_from_requirements_txt,
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
    (re.compile(r'(?i)\w*(password|passwd|pwd)\w*\s*[=:]\s*["\']?[^\s"\']{6,}'), "HARDCODED_PASSWORD", "CRITICAL"),
    (re.compile(r'(?i)\w*(api[_-]?key|apikey)\w*\s*[=:]\s*["\']?[^\s"\']{16,}'), "HARDCODED_API_KEY", "CRITICAL"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY", "CRITICAL"),
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}'), "AWS_SECRET_KEY", "CRITICAL"),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), "OPENAI_API_KEY", "CRITICAL"),
    (re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'), "PRIVATE_KEY", "CRITICAL"),
    # Broadened: matches SECRET_KEY, API_SECRET, AUTH_TOKEN, ACCESS_TOKEN, etc. —
    # not just a variable literally named "secret" or "token" with nothing else.
    # Value class widened to accept special characters (@, !, #, etc.) common
    # in real generated secrets — the old [A-Za-z0-9_\-]{16,} broke on any
    # secret containing punctuation before reaching 16 consecutive chars.
    (re.compile(r'(?i)\w*(secret|token)\w*\s*[=:]\s*["\']?[^\s"\']{16,}'), "HARDCODED_SECRET", "HIGH"),
    # Broadened: covers jdbc:, postgres://, postgresql://, mongodb://, mysql:// —
    # the previous version only matched "jdbc:" and missed common URL schemes
    # like "postgresql://" (note the "ql" suffix) and "mongodb://".
    (re.compile(r'(?i)(jdbc:[a-z]+|postgres(?:ql)?|mongodb(?:\+srv)?|mysql)://[^:\s]+:[^@\s]+@'), "DB_CREDENTIALS_IN_URL", "CRITICAL"),
    (re.compile(r'(?i)ghp_[A-Za-z0-9]{36}'), "GITHUB_TOKEN", "CRITICAL"),
    (re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*'), "HARDCODED_JWT", "HIGH"),
]

CVV_LOG_PATTERN = re.compile(r'(?i)(log|print|console)\s*[\.\(].*?(cvv|card.?number|pan|ssn)', re.DOTALL)
SQL_INJECT_PATTERN = re.compile(r'(?i)(["\']\s*\+\s*\w+|string\.format\s*\(.*?select|"SELECT.*?" \+)', re.DOTALL)

# Guard against a scanner's own source code tripping its own patterns.
# A line like: (re.compile(r'(?i)\beval\s*\('), "EVAL_INJECTION", "HIGH"),
# is a PATTERN DEFINITION, not an actual eval() call — but both regex search
# and the LLM can mistake the literal keyword for a real dangerous call.
PATTERN_DEFINITION_GUARD = re.compile(
    r're\.compile\s*\(|'          # Python: defining a regex
    r'Pattern\.compile\s*\(|'     # Java: defining a regex
    r'new\s+RegExp\s*\('          # JavaScript: defining a regex
)

# This security tool's own source and prompt files inherently discuss
# dangerous function names (eval, pickle.loads, jwt.decode, yaml.load, etc.)
# as their literal purpose — either as regex pattern definitions or as
# descriptive prose in LLM prompt instructions ("eval()/exec() with user
# input", "pickle.loads() on untrusted data"). Scanning these files with
# DANGEROUS_CALL_PATTERNS is inherently circular and produces false positives
# every time the tool's own detection logic is modified. SECRET_PATTERNS
# stays active on these files — a real leaked credential should still be
# caught regardless of which file it's in.
SELF_TOOL_FILE_MARKERS = (
    "agent/nodes.py",
    "agent/graph.py",
    "agent/main.py",
    "agent/prompts/analyzer.py",
    "agent/prompts/critique.py",
    "agent/tools/cve_checker.py",
)


def _is_self_tool_file(file_path: str) -> bool:
    """Returns True if file_path matches one of this tool's own source/prompt files."""
    normalized = file_path.replace("\\", "/").lower()
    return any(marker in normalized for marker in SELF_TOOL_FILE_MARKERS)

# Dangerous function-call patterns — language-agnostic safety net.
# LLM-only findings (SQL injection, eval, deserialization) have no database
# fact-check like CVEs do, so Mistral under-reports these inconsistently.
# This regex floor guarantees well-known dangerous one-liners are always
# caught across Java, JavaScript, and Python.
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


HUNK_HEADER_PATTERN = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')


def _extract_added_lines_with_real_line_numbers(diff_content: str) -> list[tuple[int, str, str]]:
    """
    Parses a unified diff and returns (real_file_line_number, line_content, file_path)
    for every ADDED line, using proper unified-diff hunk-header semantics.

    Critical fix: a naive `enumerate(diff.split("\\n"))` numbers every line of the
    RAW DIFF TEXT (including "diff --git" headers, "index" lines, "---"/"+++"
    markers, hunk headers, and unchanged context lines across ALL files in the
    diff) — this does NOT correspond to the actual line number within the target
    file, and produces wildly incorrect line numbers especially in multi-file PRs.

    Correct algorithm: track the "new file" line counter per hunk. Each hunk
    header "@@ -oldStart,oldCount +newStart,newCount @@" tells us the starting
    line number in the NEW file. From there:
      - a "+" line occupies the current new-file line, then counter increments
      - a " " (context) line exists in both files, counter increments
      - a "-" line was removed, doesn't exist in the new file, counter does NOT increment
    """
    results = []
    current_file = "unknown"
    new_file_line = 0  # Current line number in the target (new) file

    for line in diff_content.split("\n"):
        if line.startswith("diff --git"):
            parts = line.split(" ")
            for p in parts:
                if p.startswith("b/"):
                    current_file = p[2:]
                    break
            new_file_line = 0  # Reset — will be set by the next hunk header
            continue

        hunk_match = HUNK_HEADER_PATTERN.match(line)
        if hunk_match:
            new_file_line = int(hunk_match.group(1))
            continue

        if line.startswith("+++") or line.startswith("---") or line.startswith("index "):
            continue  # File metadata lines, not content

        if line.startswith("+"):
            # This IS the current new-file line — record it, then advance
            results.append((new_file_line, line[1:], current_file))
            new_file_line += 1
        elif line.startswith("-"):
            # Removed line — doesn't exist in the new file, don't advance counter
            continue
        else:
            # Context line (unchanged) — exists in both files, counter advances
            new_file_line += 1

    return results


def regex_prefilter_node(state: dict) -> dict:
    """
    Fast regex pre-filter. No LLM calls. Runs in milliseconds.
    Finds obvious secrets and dangerous calls, flags them to inform the LLM analyzer.
    Language-agnostic — tracks which file each hit belongs to via diff headers,
    and computes REAL target-file line numbers by parsing unified diff hunk
    headers (not a naive line count across the whole raw diff text).
    """
    log.info(f"[{state['scan_id']}] Node: regex_prefilter")

    diff = state["diff_content"]
    hits = []

    added_lines = _extract_added_lines_with_real_line_numbers(diff)

    for line_num, line_content, file_path in added_lines:
        for pattern, finding_type, severity in SECRET_PATTERNS:
            m = pattern.search(line_content)
            if m:
                hits.append({
                    "type": finding_type,
                    "severity": severity,
                    "line_content": line_content.strip(),
                    "matched_text": m.group(0),
                    "diff_line": line_num,
                    "file": file_path,
                    "source": "regex_prefilter"
                })
                break  # One hit per line is enough

        # Skip DANGEROUS_CALL_PATTERNS on:
        #  1. Lines that are themselves regex/pattern definitions (re.compile, etc.)
        #  2. This tool's own source/prompt files, which discuss these keywords
        #     as their literal purpose (pattern definitions or prompt prose)
        #  3. Comment/docstring lines — e.g. "# HIGH: eval() with user input"
        #     describing a vulnerability below it. Very common in demo/test
        #     fixtures and in real code explaining a security decision. Without
        #     this guard, the comment line itself gets flagged as a separate
        #     (redundant, wrongly-positioned) finding alongside the real one.
        stripped = line_content.strip()
        is_comment_line = stripped.startswith(("#", "//", "/*", "*", "'''", '"""'))
        is_pattern_definition = PATTERN_DEFINITION_GUARD.search(line_content)
        is_self_tool_file = _is_self_tool_file(file_path)

        if not is_pattern_definition and not is_self_tool_file and not is_comment_line:
            for pattern, finding_type, severity in DANGEROUS_CALL_PATTERNS:
                m = pattern.search(line_content)
                if m:
                    hits.append({
                        "type": finding_type,
                        "severity": severity,
                        "line_content": line_content.strip(),
                        "matched_text": m.group(0),
                        "diff_line": line_num,
                        "file": file_path,
                        "source": "regex_dangerous_call"
                    })
                    break

        # Check CVV logging
        cvv_m = CVV_LOG_PATTERN.search(line_content)
        if cvv_m:
            hits.append({
                "type": "PCI_DATA_IN_LOGS",
                "severity": "HIGH",
                "line_content": line_content.strip(),
                "matched_text": cvv_m.group(0),
                "diff_line": line_num,
                "file": file_path,
                "source": "regex_prefilter"
            })

    log.info(f"[{state['scan_id']}] Regex hits: {len(hits)}")
    return {"prefilter_hits": hits}


# ── Node 2: CVE Scanner ────────────────────────────────────────────────────────

def _manifest_actually_in_diff(diff_content: str, filename: str) -> bool:
    """
    Checks whether `filename` is ACTUALLY being changed in this diff — i.e.
    appears in a real "diff --git a/.../filename b/.../filename" header —
    rather than merely appearing as a substring anywhere in the diff text.

    Without this check, a naive `if "pom.xml" in diff` matches even when the
    only occurrence is prose in an unrelated file (e.g. a README.md that
    mentions "pom.xml", "package.json", "requirements.txt" in its own
    documentation, as this very project's README does). That false match
    then causes a doomed fetch attempt for a guessed root-level path that
    doesn't exist, and the CVE scan silently does nothing for the ACTUAL
    file that changed.
    """
    for line in diff_content.split("\n"):
        if line.startswith("diff --git") and filename in line:
            parts = line.split()
            for p in parts:
                if p.startswith("b/") and p.endswith(filename):
                    return True
    return False


def cve_scanner_node(state: dict) -> dict:
    """
    Scans dependency manifests for known CVEs via OSV API.
    Supports three ecosystems, detected independently from the diff:
      pom.xml          → Maven  (Java)      — includes BOM resolution + transitive expansion
      package.json     → npm    (JavaScript/Node.js)
      requirements.txt → PyPI   (Python)

    Uses the FULL manifest content (not just the diff) so pre-existing
    vulnerable dependencies are caught, not just newly added ones.
    """
    log.info(f"[{state['scan_id']}] Node: cve_scanner")

    diff = state["diff_content"]
    all_dependencies = []

    # ── Maven: pom.xml (BOM resolution + transitive expansion happens inside) ──
    pom_xml_content = state.get("pom_xml_content", "")
    pom_in_diff = _manifest_actually_in_diff(diff, "pom.xml")
    # If the webhook fetched full pom.xml content, use it even if pom.xml
    # was truncated out of the diff sent to the agent.
    if pom_in_diff or pom_xml_content:
        pom_path = _extract_manifest_path(diff, "pom.xml") if pom_in_diff else "pom.xml"
        log.info(f"[{state['scan_id']}] pom.xml path in repo: {pom_path}")

        if pom_xml_content:
            log.info(
                f"[{state['scan_id']}] Using full pom.xml content "
                f"({len(pom_xml_content)} chars) — scanning ALL dependencies"
            )
            deps = extract_dependencies_from_full_pom(pom_xml_content)
        else:
            log.warning(f"[{state['scan_id']}] Full pom.xml not available — falling back to diff-only")
            deps = extract_dependencies_from_diff(diff)

        for dep in deps:
            dep["pom_path"] = pom_path
            dep["manifest_path"] = pom_path
        all_dependencies.extend(deps)
    else:
        log.debug(f"[{state['scan_id']}] pom.xml not actually changed in this diff — skipping")

    # ── npm: package.json ───────────────────────────────────────────────────
    package_json_content = state.get("package_json_content", "")
    pkg_in_diff = _manifest_actually_in_diff(diff, "package.json")
    if pkg_in_diff or package_json_content:
        pkg_path = _extract_manifest_path(diff, "package.json") if pkg_in_diff else "package.json"
        log.info(f"[{state['scan_id']}] package.json detected at '{pkg_path}'")
        if package_json_content:
            deps = extract_dependencies_from_package_json(package_json_content)
            for dep in deps:
                dep["manifest_path"] = pkg_path
            all_dependencies.extend(deps)
        else:
            log.warning(f"[{state['scan_id']}] Full package.json unavailable — skipping npm CVE scan")
    else:
        log.debug(f"[{state['scan_id']}] package.json not actually changed in this diff — skipping")

    # ── PyPI: requirements.txt ──────────────────────────────────────────────
    requirements_content = state.get("requirements_txt_content", "")
    req_in_diff = _manifest_actually_in_diff(diff, "requirements.txt")
    if req_in_diff or requirements_content:
        req_path = _extract_manifest_path(diff, "requirements.txt") if req_in_diff else "requirements.txt"
        log.info(f"[{state['scan_id']}] requirements.txt detected at '{req_path}'")
        if requirements_content:
            deps = extract_dependencies_from_requirements_txt(requirements_content)
            for dep in deps:
                dep["manifest_path"] = req_path
            all_dependencies.extend(deps)
        else:
            log.warning(f"[{state['scan_id']}] Full requirements.txt unavailable — skipping PyPI CVE scan")
    else:
        log.debug(f"[{state['scan_id']}] requirements.txt not actually changed in this diff — skipping")

    if not all_dependencies:
        log.info(f"[{state['scan_id']}] No dependency manifests found in diff — skipping CVE scan")
        return {"cve_findings": []}

    log.info(
        f"[{state['scan_id']}] Checking {len(all_dependencies)} dependencies "
        f"across {len({d.get('ecosystem', 'Maven') for d in all_dependencies})} ecosystem(s) against OSV..."
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
        # ALWAYS merge regex hits — never gate this on a raw count comparison.
        # Comparing len(findings) < len(prefilter_hits) is unreliable: if Mistral
        # returns N findings that happen to equal the regex hit count but are
        # actually DIFFERENT findings (e.g. 3 secrets + XSS, missing SQL_INJECTION
        # and EVAL_INJECTION that regex found), the counts match and the merge
        # never runs — silently dropping real hits. The merge function itself
        # does proper line/evidence-based deduplication, so it's always safe
        # to call unconditionally.
        prefilter_hits = state.get("prefilter_hits", [])
        if prefilter_hits:
            before_count = len(findings)
            findings = _merge_regex_into_findings(findings, prefilter_hits)
            if len(findings) > before_count:
                log.warning(
                    f"[{state['scan_id']}] Mistral missed {len(findings) - before_count} "
                    f"regex-confirmed hit(s) — merged them in. "
                    f"LLM returned {before_count}, regex found {len(prefilter_hits)}."
                )
            log.info(f"[{state['scan_id']}] After regex merge: {len(findings)} findings")

        # ── CVE merge ────────────────────────────────────────────────────────
        # Always inject confirmed OSV CVE findings — these are facts, not LLM guesses.
        # The LLM may have already mentioned them, so we deduplicate by pom.xml line.
        cve_findings = state.get("cve_findings", [])
        if cve_findings:
            findings = _merge_cve_into_findings(findings, cve_findings)
            log.info(f"[{state['scan_id']}] After CVE merge: {len(findings)} findings")

        # ── Final proximity dedup ─────────────────────────────────────────────
        # Catches cases the evidence-overlap merge above couldn't: when Mistral
        # heavily paraphrases a finding (e.g. "Unpickling untrusted data..."
        # instead of quoting "pickle.loads(...)"), no substring overlap exists,
        # so the regex version gets ADDED as a new entry rather than replacing
        # the LLM's — leaving two rows (one wrong-lined, one correct) for the
        # same real issue. This pass collapses same-type/same-file findings
        # that land within a few lines of each other, preferring the
        # regex-sourced entry (correct, deterministic line number) when both exist.
        before_dedup = len(findings)
        findings = _deduplicate_by_proximity(findings)
        if len(findings) < before_dedup:
            log.info(
                f"[{state['scan_id']}] Proximity dedup removed "
                f"{before_dedup - len(findings)} near-duplicate finding(s)"
            )

        return {"raw_findings": findings}

    except json.JSONDecodeError as e:
        log.error(f"[{state['scan_id']}] JSON parse failed: {e}\nRaw: {raw_text[:500]}")
        # Full fallback — convert all regex hits to findings and merge CVE findings
        findings = _prefilter_to_findings(state["prefilter_hits"])
        cve_findings = state.get("cve_findings", [])
        if cve_findings:
            findings = _merge_cve_into_findings(findings, cve_findings)
        return {"raw_findings": findings}

    except Exception as e:
        log.error(f"[{state['scan_id']}] LLM analyzer failed: {e}")
        findings = _prefilter_to_findings(state.get("prefilter_hits", []))
        cve_findings = state.get("cve_findings", [])
        if cve_findings:
            findings = _merge_cve_into_findings(findings, cve_findings)
        return {"raw_findings": findings,
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

        # Filter out ground-truth findings from the ones we send to LLM for critique:
        #  - VULN_DEPENDENCY: factual OSV database lookups, not LLM guesses
        #  - regex-sourced findings (finding_id starts with "regex_"): deterministic
        #    pattern matches (secrets, eval/exec, pickle.loads, SQL injection, CVV
        #    logging). Sending these through LLM critique risks Mistral inconsistently
        #    discarding legitimate, provably-correct detections as false positives —
        #    the same reasoning that already applies to CVE findings applies here.
        findings_to_critique = [
            f for f in raw_findings
            if f.get("type") != "VULN_DEPENDENCY"
            and not str(f.get("finding_id", "")).startswith("regex_")
        ]

        critique_map = {}
        if findings_to_critique:
            log.info(f"[{state['scan_id']}] Critiquing {len(findings_to_critique)} non-CVE, non-regex findings...")
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
            log.info(f"[{state['scan_id']}] No non-CVE, non-regex findings to critique. Skipping critique LLM.")

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
            elif str(fid).startswith("regex_"):
                # Deterministic regex-confirmed finding — auto-confirm, skip LLM critique.
                # Bypassing critique guarantees these are never inconsistently discarded
                # across runs, and keeps our own correctly-computed line/file authoritative.
                confidence = finding.get("confidence", 0.85)
                critiqued.append({
                    **finding,
                    "initial_confidence": confidence,
                    "final_confidence": confidence,
                    "critique_verdict": "CONFIRMED",
                    "critique_rationale": "Deterministic regex pattern match — skipped critique."
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

# Mapping of specific detector types to general vulnerability families.
# Used to deduplicate generic LLM findings (e.g. SECRET_EXPOSURE) against
# specific regex hits (e.g. HARDCODED_API_KEY).
TYPE_FAMILY = {
    # Mistral generic types
    "SECRET_EXPOSURE": "SECRET",
    "PRIVATE_KEY": "PRIVATE_KEY",
    "DB_CREDENTIALS": "DB_CREDENTIALS",
    "SQL_INJECTION": "SQL_INJECTION",
    "VULN_DEPENDENCY": "VULN_DEPENDENCY",
    "PCI_VIOLATION": "PCI_VIOLATION",
    "BROKEN_AUTH": "BROKEN_AUTH",
    "INSECURE_DESERIALIZE": "INSECURE_DESERIALIZE",
    "CSRF_DISABLED": "CSRF_DISABLED",
    "CORS_WILDCARD": "CORS_WILDCARD",
    "SENSITIVE_IN_LOGS": "SENSITIVE_IN_LOGS",
    "HARDCODED_URL": "HARDCODED_URL",

    # Specific regex types mapped to families
    "HARDCODED_PASSWORD": "SECRET",
    "HARDCODED_API_KEY": "SECRET",
    "AWS_ACCESS_KEY": "SECRET",
    "AWS_SECRET_KEY": "SECRET",
    "OPENAI_API_KEY": "SECRET",
    "HARDCODED_SECRET": "SECRET",
    "GITHUB_TOKEN": "SECRET",
    "HARDCODED_JWT": "SECRET",
    
    "DB_CREDENTIALS_IN_URL": "DB_CREDENTIALS",
    
    "PCI_DATA_IN_LOGS": "PCI_VIOLATION",
    
    "EVAL_INJECTION": "INSECURE_DESERIALIZE",
    "COMMAND_INJECTION": "INSECURE_DESERIALIZE",
    
    "XSS_RISK": "XSS_RISK"
}

def _get_type_family(t: str) -> str:
    return TYPE_FAMILY.get(t, t)


def _deduplicate_by_proximity(findings: list, line_window: int = 15) -> list:
    """
    Collapses findings that are almost certainly duplicates of the same real
    issue: same type family, same file, and within `line_window` lines of each other.

    This is a safety-net pass for cases the evidence-overlap merge can't catch
    — specifically when Mistral paraphrases a finding so differently from the
    regex hit's raw line content that no substring overlap exists (e.g.
    describing pickle.loads() as "unpickling untrusted data" instead of
    quoting the call). When a group of near-duplicates is found, prefer:
      1. A regex-sourced entry (finding_id starts with "regex_") — its line
         number is deterministically correct via diff-hunk parsing.
      2. Otherwise, the one with the highest confidence.
    """
    if len(findings) <= 1:
        return findings

    groups: list[list[dict]] = []
    used = [False] * len(findings)

    for i, f in enumerate(findings):
        if used[i]:
            continue
        group = [f]
        used[i] = True
        f_type = f.get("type", "")
        f_family = _get_type_family(f_type)
        f_file = f.get("file", "unknown")
        f_line = f.get("line", -1)

        # Secrets/Credentials require an exact line match to prevent collapsing
        # separate secrets on adjacent lines. Other vulnerabilities use the wider window.
        current_window = 0 if f_family in ("SECRET", "DB_CREDENTIALS") else line_window

        for j in range(i + 1, len(findings)):
            if used[j]:
                continue
            g = findings[j]
            g_type = g.get("type", "")
            g_family = _get_type_family(g_type)
            g_line = g.get("line", -1)

            same_family = f_family == g_family
            same_file = g.get("file", "unknown") == f_file

            if (
                same_family
                and same_file
                and f_line >= 0 and g_line >= 0
                and abs(g_line - f_line) <= current_window
            ):
                group.append(g)
                used[j] = True

        groups.append(group)

    deduped = []
    for group in groups:
        if len(group) == 1:
            deduped.append(group[0])
            continue

        # Prefer a regex-sourced entry (deterministic, correct line number)
        regex_entries = [f for f in group if str(f.get("finding_id", "")).startswith("regex_")]
        if regex_entries:
            deduped.append(max(regex_entries, key=lambda f: f.get("confidence", 0)))
        else:
            deduped.append(max(group, key=lambda f: f.get("confidence", 0)))

    return deduped


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

    Two cases per regex hit:
      1. No overlapping LLM finding exists → ADD the regex finding (new detection).
      2. An overlapping LLM finding exists (same secret/call, evidence-matched)
         → REPLACE it with the regex version instead of just skipping.

    Why replace instead of skip: our regex line number is computed via proper
    unified-diff hunk parsing and is provably correct, whereas the LLM's own
    self-reported "line" field is frequently wrong (LLMs are unreliable at
    precise line-counting over more than a few dozen lines — commonly off by
    a consistent offset, e.g. miscounting past a docstring or blank lines).
    Replacing guarantees the final report always shows the correct line/file,
    regardless of what line number Mistral guessed.
    """
    merged = list(llm_findings)

    severity_confidence = {
        "CRITICAL": 0.93,
        "HIGH": 0.88,
        "MEDIUM": 0.70,
        "LOW": 0.50,
    }

    for i, hit in enumerate(prefilter_hits):
        line_content_lower = hit["line_content"].lower()[:80]
        matched_text_lower = hit.get("matched_text", "").lower().strip()
        hit_file = hit.get("file", "unknown")
        diff_line = hit.get("diff_line", 0)

        regex_finding = {
            "finding_id": f"regex_{i:03d}",
            "severity": hit["severity"],
            "type": hit["type"],
            "file": hit_file,
            "line": diff_line,
            "evidence": hit["line_content"][:200],
            "confidence": severity_confidence.get(hit["severity"], 0.75),
            "policy_ref": "SEC-001",
            "remediation": "Move to environment variables or a secrets manager (e.g. AWS Secrets Manager, Vault)."
        }

        # Look for an existing LLM finding that overlaps this same hit.
        #
        # Two ways to detect overlap, BOTH gated on matching "type family" and "file"
        # first (to avoid false collisions between unrelated findings):
        #   1. Full-line substring overlap (works when Mistral quotes the
        #      line close to verbatim)
        #   2. matched_text overlap (e.g. "eval(", "pickle.loads(") — catches
        #      cases where Mistral PARAPHRASES the evidence in its own words
        #      (e.g. "Using eval() on user input allows RCE" instead of
        #      quoting "risk_score = eval(formula)" directly). Gating on
        #      type family + file keeps this safe from unrelated false matches.
        overlap_index = None
        for idx, f in enumerate(merged):
            same_type = _get_type_family(f.get("type", "")) == _get_type_family(hit["type"])
            same_file = f.get("file", "unknown") in (hit_file, "unknown") or hit_file == "unknown"
            if not (same_type and same_file):
                continue

            existing_ev = f.get("evidence", "").lower()[:200]

            full_line_overlap = (
                len(existing_ev) > 10 and
                (line_content_lower in existing_ev or existing_ev in line_content_lower)
            )
            signature_overlap = (
                len(matched_text_lower) >= 4 and matched_text_lower in existing_ev
            )

            if full_line_overlap or signature_overlap:
                overlap_index = idx
                break

        if overlap_index is not None:
            # Replace — regex-computed line/file wins over the LLM's guess
            merged[overlap_index] = regex_finding
        else:
            merged.append(regex_finding)

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


# Alias — keeps backward compatibility if graph.py uses old name
dependency_scanner_node = cve_scanner_node
