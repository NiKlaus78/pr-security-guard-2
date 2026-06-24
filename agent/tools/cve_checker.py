"""
CVE Checker Tool

Scans pom.xml for Maven dependencies and queries the OSV API for known CVEs.

OSV API: https://api.osv.dev — completely free, no API key required.

Two-step approach (required because OSV batch returns stripped objects):
  Step 1: POST /v1/querybatch  → get list of vulnerability IDs per package
  Step 2: POST /v1/vulns/{id}  → fetch full details (CVSS, aliases, summary)
"""

import re
import logging
import httpx

log = logging.getLogger(__name__)

OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL   = "https://api.osv.dev/v1/vulns/{vuln_id}"
MIN_CVSS_SCORE = 7.0
REQUEST_TIMEOUT = 15


# ── Regex patterns for pom.xml parsing ────────────────────────────────────────

GROUP_RE    = re.compile(r'<groupId>([^<]+)</groupId>')
ARTIFACT_RE = re.compile(r'<artifactId>([^<]+)</artifactId>')
VERSION_RE  = re.compile(r'<version>([^<${}]+)</version>')
DEP_BLOCK   = re.compile(r'<dependency>(.*?)</dependency>', re.DOTALL | re.IGNORECASE)


# ── Dependency Extraction ──────────────────────────────────────────────────────

def extract_dependencies_from_full_pom(pom_content: str) -> list[dict]:
    """
    Extracts ALL Maven dependencies from full pom.xml content.
    Catches pre-existing vulnerable dependencies, not just newly added ones.
    """
    dependencies = []

    for match in DEP_BLOCK.finditer(pom_content):
        block = match.group(1)

        group_m    = GROUP_RE.search(block)
        artifact_m = ARTIFACT_RE.search(block)
        version_m  = VERSION_RE.search(block)

        if not (group_m and artifact_m and version_m):
            continue

        version = version_m.group(1).strip()
        if version.startswith('$'):
            continue  # Skip unresolved property references

        line_num = pom_content[:match.start()].count('\n') + 1

        dependencies.append({
            "group_id":    group_m.group(1).strip(),
            "artifact_id": artifact_m.group(1).strip(),
            "version":     version,
            "line_number": line_num
        })

    log.info(f"Extracted {len(dependencies)} dependencies from full pom.xml")
    return dependencies


def extract_dependencies_from_diff(diff_content: str) -> list[dict]:
    """
    Fallback: extracts only ADDED Maven dependencies from a unified diff.
    Only catches new dependencies, not pre-existing ones.
    """
    dependencies = []
    file_sections = re.split(r'diff --git ', diff_content)

    for section in file_sections:
        if 'pom.xml' not in section.split('\n')[0]:
            continue

        lines = section.split('\n')
        added_lines = []

        for i, line in enumerate(lines, 1):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append((i, line[1:]))

        if added_lines:
            combined = '\n'.join(content for _, content in added_lines)
            for match in DEP_BLOCK.finditer(combined):
                block = match.group(1)
                group_m    = GROUP_RE.search(block)
                artifact_m = ARTIFACT_RE.search(block)
                version_m  = VERSION_RE.search(block)

                if group_m and artifact_m and version_m:
                    version = version_m.group(1).strip()
                    if not version.startswith('$'):
                        dependencies.append({
                            "group_id":    group_m.group(1).strip(),
                            "artifact_id": artifact_m.group(1).strip(),
                            "version":     version,
                            "line_number": added_lines[0][0] if added_lines else 0
                        })

    log.info(f"Extracted {len(dependencies)} dependencies from diff")
    return dependencies


# ── OSV API — Two-Step Lookup ──────────────────────────────────────────────────

def check_dependencies_for_cves(dependencies: list[dict]) -> list[dict]:
    """
    Main entry point. For each dependency:
      Step 1 — batch query OSV to find which packages have known vulnerabilities
      Step 2 — fetch full vuln details to get CVSS scores and summaries
    Returns list of findings above MIN_CVSS_SCORE threshold.
    """
    if not dependencies:
        return []

    # ── Step 1: Batch query to get vulnerability IDs ──────────────────────────
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

    try:
        response = httpx.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        batch_results = response.json().get("results", [])
    except Exception as e:
        log.error(f"OSV batch query failed: {e}")
        return []

    # ── Step 2: Collect all unique vuln IDs that need full details ────────────
    # Map: vuln_id → dep (so we know which dependency triggered it)
    vuln_id_to_dep = {}
    for dep, result in zip(dependencies, batch_results):
        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id")
            if vuln_id and vuln_id not in vuln_id_to_dep:
                vuln_id_to_dep[vuln_id] = dep

    if not vuln_id_to_dep:
        log.info("OSV: no vulnerabilities found for any dependency")
        return []

    log.info(f"OSV: found {len(vuln_id_to_dep)} unique vulnerability IDs — fetching full details")

    # ── Step 3: Fetch full details for each vulnerability ─────────────────────
    cve_findings = []
    for vuln_id, dep in vuln_id_to_dep.items():
        full_details = _fetch_vuln_details(vuln_id)
        if not full_details:
            continue

        finding = _build_finding(full_details, dep)
        if finding:
            cve_findings.append(finding)
            log.info(
                f"CVE confirmed: {dep['group_id']}:{dep['artifact_id']}:{dep['version']} "
                f"→ {finding['cve_id']} severity={finding['severity']} "
                f"cvss={finding.get('cvss_score', 'N/A')}"
            )

    log.info(f"CVE scan complete — {len(cve_findings)} findings above threshold")
    return cve_findings


def _fetch_vuln_details(vuln_id: str) -> dict | None:
    """
    Fetches full vulnerability details from OSV including CVSS scores,
    aliases (CVE IDs), summary, and affected version ranges.
    """
    try:
        url = OSV_VULN_URL.format(vuln_id=vuln_id)
        response = httpx.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        log.warning(f"Failed to fetch vuln details for {vuln_id}: {e}")
        return None


def _build_finding(vuln: dict, dep: dict) -> dict | None:
    """
    Converts a full OSV vulnerability object into our standard finding format.
    Extracts CVSS score, determines severity, and applies threshold filter.
    """
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", "No description available.")
    aliases = vuln.get("aliases", [])

    # Prefer CVE ID over GHSA ID for display
    cve_id = vuln_id
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # ── Extract CVSS score ─────────────────────────────────────────────────────
    # OSV full details have severity array with CVSS vector strings
    # and database_specific may have numeric scores
    cvss_score = 0.0
    severity_label = ""

    # Try severity array first (CVSS vector strings)
    for sev in vuln.get("severity", []):
        sev_type  = sev.get("type", "")
        sev_score = sev.get("score", "")

        # Some OSV entries put numeric score directly
        try:
            cvss_score = float(sev_score)
            break
        except (ValueError, TypeError):
            pass

        # Parse CVSS v3 vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        if "CVSS" in sev_type and isinstance(sev_score, str) and "/" in sev_score:
            # Extract base score from vector if present
            # Format sometimes: "CVSS:3.1/AV:N/.../BaseScore:10.0"
            base_match = re.search(r'BaseScore[:/](\d+\.?\d*)', sev_score, re.IGNORECASE)
            if base_match:
                try:
                    cvss_score = float(base_match.group(1))
                    break
                except ValueError:
                    pass

    # Try database_specific (GitHub Advisory format)
    db_specific = vuln.get("database_specific", {})
    if cvss_score == 0.0:
        # GitHub Advisory Database format
        if "cvss" in db_specific:
            try:
                cvss_score = float(db_specific["cvss"])
            except (ValueError, TypeError):
                pass

        # Try nested CVSS
        cvss_data = db_specific.get("cvss_v3") or db_specific.get("cvss_v2") or {}
        if cvss_score == 0.0 and isinstance(cvss_data, dict):
            try:
                cvss_score = float(cvss_data.get("baseScore", 0))
            except (ValueError, TypeError):
                pass

    # Use severity string as final fallback
    severity_label = db_specific.get("severity", "").upper()
    if cvss_score == 0.0:
        cvss_map = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 6.5, "MEDIUM": 6.5, "LOW": 3.5}
        cvss_score = cvss_map.get(severity_label, 0.0)

    # ── Apply threshold — but always include CRITICAL/HIGH by label ───────────
    is_high_severity = severity_label in ("CRITICAL", "HIGH")
    if cvss_score < MIN_CVSS_SCORE and not is_high_severity:
        log.debug(f"Skipping {cve_id} — CVSS {cvss_score} below threshold, severity={severity_label}")
        return None

    # ── Map to our severity levels ─────────────────────────────────────────────
    if cvss_score >= 9.0 or severity_label == "CRITICAL":
        severity = "CRITICAL"
    elif cvss_score >= 7.0 or severity_label == "HIGH":
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    dep_coords = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"

    return {
        "finding_id":  f"cve_{cve_id.replace('-', '_').replace(':', '_').lower()}",
        "severity":    severity,
        "type":        "VULN_DEPENDENCY",
        "file":        "pom.xml",
        "line":        dep.get("line_number", 0),
        "evidence":    f"{dep_coords} → {cve_id}",
        "confidence":  0.98,
        "policy_ref":  "SEC-005",
        "remediation": (
            f"Upgrade {dep['artifact_id']} to a patched version. "
            f"See https://osv.dev/vulnerability/{vuln_id} for affected and fixed versions."
        ),
        # Extra metadata for prompt context
        "cve_id":     cve_id,
        "cvss_score": cvss_score,
        "summary":    summary[:300],
        "osv_id":     vuln_id
    }
