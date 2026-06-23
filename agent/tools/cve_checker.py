"""
CVE Checker Tool

Scans pom.xml diffs for added/changed Maven dependencies and queries
the OSV (Open Source Vulnerabilities) API to find known CVEs.

OSV API: https://api.osv.dev — completely free, no API key required.
Covers: NVD, GitHub Advisory, GHSA, and many other databases.

Used by the cve_scanner_node in the LangGraph pipeline as Stage 2,
sitting between regex_prefilter and llm_analyzer.
"""

import re
import logging
import httpx

log = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MIN_CVSS_SCORE = 7.0          # Only flag HIGH and CRITICAL CVEs
REQUEST_TIMEOUT = 10          # Seconds per API call


# ── Dependency Extraction ──────────────────────────────────────────────────────

# Matches added lines in pom.xml diffs containing groupId, artifactId, version
GROUP_RE    = re.compile(r'<groupId>([^<]+)</groupId>')
ARTIFACT_RE = re.compile(r'<artifactId>([^<]+)</artifactId>')
VERSION_RE  = re.compile(r'<version>([^<${}]+)</version>')


def extract_dependencies_from_diff(diff_content: str) -> list[dict]:
    """
    Parses a unified diff to extract Maven dependency blocks that were ADDED.
    Only looks at lines starting with + (added lines).

    Returns a list of dicts: [{group_id, artifact_id, version, line_number}]
    """
    dependencies = []

    # Split diff into per-file sections
    file_sections = re.split(r'diff --git ', diff_content)

    for section in file_sections:
        # Only process pom.xml files
        if 'pom.xml' not in section.split('\n')[0]:
            continue

        lines = section.split('\n')
        added_block = []
        block_start_line = 0

        # Collect consecutive added lines that form a dependency block
        for i, line in enumerate(lines, 1):
            if line.startswith('+') and not line.startswith('+++'):
                added_block.append((i, line[1:]))  # Strip leading +
            else:
                # Process accumulated block
                if added_block:
                    deps = _parse_dependency_block(added_block)
                    dependencies.extend(deps)
                    added_block = []

        # Process any remaining block
        if added_block:
            deps = _parse_dependency_block(added_block)
            dependencies.extend(deps)

    log.debug(f"Extracted {len(dependencies)} dependencies from pom.xml diff")
    return dependencies


def _parse_dependency_block(lines: list[tuple]) -> list[dict]:
    """
    Given a list of (line_num, content) tuples from an added block,
    finds complete <dependency> blocks and extracts their coordinates.
    """
    combined_text = '\n'.join(content for _, content in lines)
    results = []

    # Find dependency blocks in the combined text
    dep_pattern = re.compile(
        r'<dependency>(.*?)</dependency>',
        re.DOTALL | re.IGNORECASE
    )

    for match in dep_pattern.finditer(combined_text):
        block = match.group(1)

        group_match    = GROUP_RE.search(block)
        artifact_match = ARTIFACT_RE.search(block)
        version_match  = VERSION_RE.search(block)

        if group_match and artifact_match and version_match:
            version = version_match.group(1).strip()

            # Skip property references like ${spring.version}
            if version.startswith('$'):
                continue

            # Find approximate line number (first line of the block)
            line_num = lines[0][0] if lines else 0

            results.append({
                "group_id":    group_match.group(1).strip(),
                "artifact_id": artifact_match.group(1).strip(),
                "version":     version,
                "line_number": line_num
            })

    return results


# ── OSV API Queries ────────────────────────────────────────────────────────────

def check_dependencies_for_cves(dependencies: list[dict]) -> list[dict]:
    """
    Queries the OSV batch API for all dependencies at once.
    Returns a list of CVE findings with severity, CVSS score, and description.

    Uses batch endpoint to minimise latency (1 request for all deps).
    """
    if not dependencies:
        return []

    # Build batch query payload
    queries = [
        {
            "version": dep["version"],
            "package": {
                "name": f"{dep['group_id']}:{dep['artifact_id']}",
                "ecosystem": "Maven"
            }
        }
        for dep in dependencies
    ]

    payload = {"queries": queries}

    try:
        response = httpx.post(
            OSV_BATCH_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        batch_results = response.json().get("results", [])

    except httpx.TimeoutException:
        log.warning("OSV API timed out — falling back to individual queries")
        return _check_individual_fallback(dependencies)

    except Exception as e:
        log.error(f"OSV batch query failed: {e}")
        return []

    # Map results back to dependencies and extract findings
    cve_findings = []
    for dep, result in zip(dependencies, batch_results):
        vulns = result.get("vulns", [])
        if not vulns:
            continue

        for vuln in vulns:
            finding = _vuln_to_finding(vuln, dep)
            if finding:
                cve_findings.append(finding)
                log.info(
                    f"CVE found: {dep['group_id']}:{dep['artifact_id']}:{dep['version']} "
                    f"→ {finding['cve_id']} CVSS={finding['cvss_score']}"
                )

    return cve_findings


def _check_individual_fallback(dependencies: list[dict]) -> list[dict]:
    """
    Fallback: query OSV individually per dependency.
    Used when batch endpoint times out.
    """
    findings = []
    for dep in dependencies:
        try:
            payload = {
                "version": dep["version"],
                "package": {
                    "name": f"{dep['group_id']}:{dep['artifact_id']}",
                    "ecosystem": "Maven"
                }
            }
            response = httpx.post(OSV_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            vulns = response.json().get("vulns", [])

            for vuln in vulns:
                finding = _vuln_to_finding(vuln, dep)
                if finding:
                    findings.append(finding)

        except Exception as e:
            log.warning(f"OSV query failed for {dep['group_id']}:{dep['artifact_id']}: {e}")
            continue

    return findings


def _vuln_to_finding(vuln: dict, dep: dict) -> dict | None:
    """
    Converts an OSV vulnerability object into our standard finding format.
    Returns None if CVSS score is below MIN_CVSS_SCORE threshold.
    """
    vuln_id      = vuln.get("id", "UNKNOWN")
    summary      = vuln.get("summary", "No description available.")
    aliases      = vuln.get("aliases", [])

    # Extract CVE ID from aliases (OSV uses GHSA IDs primarily)
    cve_id = vuln_id
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # Extract CVSS score from severity list
    cvss_score = 0.0
    severity_label = "UNKNOWN"
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
            score_str = sev.get("score", "")
            # CVSS vector string — extract base score
            try:
                # Format: CVSS:3.1/AV:N/AC:L/... → need to query for numeric score
                # OSV sometimes provides numeric score in database_specific
                pass
            except Exception:
                pass

    # Try database_specific for numeric CVSS
    db_specific = vuln.get("database_specific", {})
    if "cvss" in db_specific:
        try:
            cvss_score = float(db_specific["cvss"])
        except (ValueError, TypeError):
            pass

    # Also check severity string as fallback
    severity_str = db_specific.get("severity", "").upper()
    if cvss_score == 0.0:
        if severity_str == "CRITICAL":
            cvss_score = 9.5
        elif severity_str == "HIGH":
            cvss_score = 8.0
        elif severity_str == "MODERATE":
            cvss_score = 6.5
        elif severity_str == "LOW":
            cvss_score = 3.5

    # Skip below threshold
    if cvss_score < MIN_CVSS_SCORE and severity_str not in ("CRITICAL", "HIGH"):
        return None

    # Map to severity
    if cvss_score >= 9.0 or severity_str == "CRITICAL":
        severity = "CRITICAL"
    elif cvss_score >= 7.0 or severity_str == "HIGH":
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    dep_coords = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"

    return {
        "finding_id": f"cve_{cve_id.replace('-', '_').lower()}",
        "severity": severity,
        "type": "VULN_DEPENDENCY",
        "file": "pom.xml",
        "line": dep.get("line_number", 0),
        "evidence": f"{dep_coords} is vulnerable to {cve_id}",
        "confidence": 0.98,      # OSV is a factual database — very high confidence
        "policy_ref": "SEC-005",
        "remediation": (
            f"Upgrade {dep['artifact_id']} to a patched version. "
            f"See https://osv.dev/vulnerability/{vuln_id} for fixed versions."
        ),
        # Extra metadata passed to the LLM for context
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "summary": summary[:300],
        "osv_id": vuln_id
    }
