"""
CVE Checker Tool — v4 (parent-managed deps, parallel fetch, robust severity)

Two-step OSV lookup:
  Step 1: POST /v1/querybatch  → get vuln IDs per package
  Step 2: GET  /v1/vulns/{id}  → fetch full details in PARALLEL

Key design decisions:
  - Scans ALL dependencies — including parent-managed ones without <version> tags
  - Resolves versions from <dependencyManagement> blocks and parent POM BOM
  - Deps with unresolvable versions still queried via OSV (no version → all vulns)
  - Parallel vuln detail fetching (ThreadPoolExecutor) — avoids 7-14s sequential timeout
  - No fragile CVSS v4 vector parsing — use OSV severity label as primary signal
  - Include CRITICAL / HIGH / MODERATE, exclude LOW and unknown
  - Full debug logging at every step so failures are never silent
"""

import re
import logging
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

log = logging.getLogger(__name__)

OSV_BATCH_URL   = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL    = "https://api.osv.dev/v1/vulns/{vuln_id}"
REQUEST_TIMEOUT = 12           # per request
PARALLEL_WORKERS = 5           # fetch this many vuln details simultaneously
MAX_VULNS       = 30           # cap to avoid runaway API calls on huge pom files

# Severity labels that we treat as actionable
ACTIONABLE_SEVERITIES = {"CRITICAL", "HIGH", "MODERATE", "MEDIUM"}

# Severity → our internal level
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",    # OSV "MODERATE" → our "MEDIUM" (WARN, not BLOCK)
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}


# ── pom.xml regex patterns ─────────────────────────────────────────────────────

GROUP_RE    = re.compile(r'<groupId>([^<]+)</groupId>')
ARTIFACT_RE = re.compile(r'<artifactId>([^<]+)</artifactId>')
VERSION_RE  = re.compile(r'<version>([^<]+)</version>')
DEP_BLOCK   = re.compile(r'<dependency>(.*?)</dependency>', re.DOTALL | re.IGNORECASE)
PROPS_TAG   = re.compile(r'<([^/>\s][^>]*)>([^<]+)</\1>')


# ── Dependency Extraction ──────────────────────────────────────────────────────

def extract_dependencies_from_full_pom(pom_content: str) -> list[dict]:
    """
    Extracts ALL Maven dependencies from full pom.xml content.
    Resolves ${property} references using the <properties> block.
    For parent-managed deps (no <version> tag), resolves version from
    <dependencyManagement> or includes them without a version so OSV
    can still return known vulnerabilities for the package.
    """
    # Step 1: Build property map for version resolution
    properties = {}
    props_block = re.search(
        r'<properties>(.*?)</properties>', pom_content, re.DOTALL | re.IGNORECASE
    )
    if props_block:
        for m in PROPS_TAG.finditer(props_block.group(1)):
            properties[m.group(1).strip()] = m.group(2).strip()
        log.debug(f"Resolved {len(properties)} pom properties")

    # Step 2: Extract parent POM info for version resolution context
    parent_info = _extract_parent_info(pom_content)
    if parent_info:
        log.info(
            f"Parent POM: {parent_info['group_id']}:"
            f"{parent_info['artifact_id']}:{parent_info['version']}"
        )

    # Step 3: Build a version map from <dependencyManagement> if present
    managed_versions = _resolve_managed_versions(pom_content, properties)
    if managed_versions:
        log.info(f"Resolved {len(managed_versions)} managed dependency versions")

    dependencies = []

    for match in DEP_BLOCK.finditer(pom_content):
        block = match.group(1)

        group_m    = GROUP_RE.search(block)
        artifact_m = ARTIFACT_RE.search(block)
        version_m  = VERSION_RE.search(block)

        if not (group_m and artifact_m):
            continue

        group_id = group_m.group(1).strip()
        artifact_id = artifact_m.group(1).strip()
        line_num = pom_content[:match.start()].count('\n') + 1
        version_source = "explicit"  # tracks where version came from

        if version_m:
            raw_version = version_m.group(1).strip()

            # Resolve ${property} reference
            if raw_version.startswith('${') and raw_version.endswith('}'):
                prop_key = raw_version[2:-1]
                resolved = properties.get(prop_key, "")
                if not resolved:
                    log.debug(f"Unresolvable property: {raw_version} for {group_id}:{artifact_id}")
                    raw_version = ""
                    version_source = "unresolved_property"
                else:
                    raw_version = resolved
                    version_source = "property"

            # Skip anything still looking like an unresolved reference
            if raw_version.startswith('$'):
                raw_version = ""
                version_source = "unresolved_property"
        else:
            # No <version> tag — try to resolve from dependencyManagement or parent
            raw_version = ""
            version_source = "parent_managed"

        # Try managed version resolution if we don't have a version yet
        if not raw_version:
            managed_key = f"{group_id}:{artifact_id}"
            if managed_key in managed_versions:
                raw_version = managed_versions[managed_key]
                version_source = "dependency_management"
                log.debug(f"Resolved {managed_key} → {raw_version} from dependencyManagement")

        dependencies.append({
            "group_id":       group_id,
            "artifact_id":    artifact_id,
            "version":        raw_version,     # may be "" for parent-managed deps
            "line_number":    line_num,
            "version_source": version_source,   # helps set confidence level downstream
        })

    log.info(f"Extracted {len(dependencies)} dependencies from full pom.xml")
    versioned = sum(1 for d in dependencies if d['version'])
    unversioned = sum(1 for d in dependencies if not d['version'])
    log.info(f"  versioned={versioned}, parent-managed (no version)={unversioned}")
    for d in dependencies:
        ver_display = d['version'] or f"(managed by parent — {d['version_source']})"
        log.debug(f"  dep: {d['group_id']}:{d['artifact_id']}:{ver_display}")

    return dependencies


def extract_dependencies_from_diff(diff_content: str) -> list[dict]:
    """
    Fallback: extracts only ADDED dependencies from a unified diff.
    Used when full pom.xml fetch failed.
    """
    dependencies = []

    for section in re.split(r'diff --git ', diff_content):
        if 'pom.xml' not in section.split('\n')[0]:
            continue

        added_text = '\n'.join(
            line[1:] for line in section.split('\n')
            if line.startswith('+') and not line.startswith('+++')
        )

        for match in DEP_BLOCK.finditer(added_text):
            block = match.group(1)
            g = GROUP_RE.search(block)
            a = ARTIFACT_RE.search(block)
            v = VERSION_RE.search(block)
            if g and a:
                ver = v.group(1).strip() if v else ""
                if ver.startswith('$'):
                    ver = ""
                dependencies.append({
                    "group_id":       g.group(1).strip(),
                    "artifact_id":    a.group(1).strip(),
                    "version":        ver,
                    "line_number":    0,
                    "version_source": "explicit" if ver else "unknown",
                })

    log.info(f"Extracted {len(dependencies)} dependencies from diff (fallback)")
    return dependencies


# ── Parent POM & Dependency Management Resolution ─────────────────────────────

def _extract_parent_info(pom_content: str) -> dict | None:
    """
    Extracts the <parent> block from a pom.xml to identify the parent POM.
    Returns dict with group_id, artifact_id, version or None.
    """
    parent_block = re.search(
        r'<parent>(.*?)</parent>', pom_content, re.DOTALL | re.IGNORECASE
    )
    if not parent_block:
        return None

    block = parent_block.group(1)
    g = GROUP_RE.search(block)
    a = ARTIFACT_RE.search(block)
    v = VERSION_RE.search(block)

    if g and a and v:
        return {
            "group_id":    g.group(1).strip(),
            "artifact_id": a.group(1).strip(),
            "version":     v.group(1).strip(),
        }
    return None


def _resolve_managed_versions(
    pom_content: str, properties: dict
) -> dict[str, str]:
    """
    Extracts version info from <dependencyManagement> blocks.
    Returns a map of "groupId:artifactId" → "version" for managed deps.

    This handles cases where versions are declared in dependencyManagement
    (either in this POM or imported via parent). For deps managed by a
    parent BOM that isn't inlined, the version will remain unresolved.
    """
    managed: dict[str, str] = {}

    # Find <dependencyManagement><dependencies>...</dependencies></dependencyManagement>
    dm_block = re.search(
        r'<dependencyManagement>\s*<dependencies>(.*?)</dependencies>\s*</dependencyManagement>',
        pom_content, re.DOTALL | re.IGNORECASE
    )
    if not dm_block:
        return managed

    for match in DEP_BLOCK.finditer(dm_block.group(1)):
        block = match.group(1)
        g = GROUP_RE.search(block)
        a = ARTIFACT_RE.search(block)
        v = VERSION_RE.search(block)

        if g and a and v:
            version = v.group(1).strip()
            # Resolve property references
            if version.startswith('${') and version.endswith('}'):
                prop_key = version[2:-1]
                version = properties.get(prop_key, "")
            if version and not version.startswith('$'):
                key = f"{g.group(1).strip()}:{a.group(1).strip()}"
                managed[key] = version
                log.debug(f"  dependencyManagement: {key} → {version}")

    return managed


# ── OSV API — Two-Step Lookup with Parallel Fetching ──────────────────────────

def check_dependencies_for_cves(dependencies: list[dict]) -> list[dict]:
    """
    Main entry point.
    Step 1: Batch query → get vulnerability IDs per dependency
    Step 2: Parallel fetch full details → extract severity + CVE alias
    Returns list of findings for CRITICAL / HIGH / MODERATE severity.
    """
    if not dependencies:
        return []

    # ── Step 1: Batch query ───────────────────────────────────────────────────
    log.info(f"OSV batch query for {len(dependencies)} dependencies...")

    queries = []
    for dep in dependencies:
        query = {
            "package": {
                "name":      f"{dep['group_id']}:{dep['artifact_id']}",
                "ecosystem": "Maven"
            }
        }
        # Only include version if we have one — OSV without version returns
        # ALL known vulns for that package (we filter by severity downstream)
        if dep.get("version"):
            query["version"] = dep["version"]
        else:
            log.info(
                f"  {dep['group_id']}:{dep['artifact_id']} — "
                f"no version (querying all known vulns)"
            )
        queries.append(query)

    try:
        resp = httpx.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
        log.info(f"OSV batch response: {len(batch_results)} result sets")
    except httpx.TimeoutException:
        log.error("OSV batch query timed out")
        return []
    except Exception as e:
        log.error(f"OSV batch query failed: {type(e).__name__}: {e}")
        return []

    # ── Map vuln_id → dep (deduplicated) ──────────────────────────────────────
    vuln_to_dep: dict[str, dict] = {}
    for dep, result in zip(dependencies, batch_results):
        vulns = result.get("vulns", [])
        ver_display = dep['version'] or '(parent-managed)'
        dep_key = f"{dep['group_id']}:{dep['artifact_id']}:{ver_display}"
        log.info(f"  {dep_key} → {len(vulns)} vulns")
        for v in vulns:
            vid = v.get("id", "")
            if vid and vid not in vuln_to_dep:
                vuln_to_dep[vid] = dep

    if not vuln_to_dep:
        log.info("No vulnerabilities found for any dependency")
        return []

    total_ids = len(vuln_to_dep)
    log.info(f"Found {total_ids} unique vuln IDs — fetching full details in parallel...")

    # Cap to avoid runaway calls on huge dependency lists
    vuln_items = list(vuln_to_dep.items())[:MAX_VULNS]
    if len(vuln_to_dep) > MAX_VULNS:
        log.warning(f"Capped vuln detail fetches at {MAX_VULNS} (had {total_ids})")

    # ── Step 2: Parallel fetch vuln details ───────────────────────────────────
    cve_findings = []
    failed = 0

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
        future_map = {
            pool.submit(_fetch_and_build, vid, dep): vid
            for vid, dep in vuln_items
        }

        for future in as_completed(future_map, timeout=30):
            vid = future_map[future]
            try:
                finding = future.result()
                if finding:
                    cve_findings.append(finding)
                    log.info(
                        f"CVE included: {finding['cve_id']} "
                        f"severity={finding['severity']} "
                        f"for {finding.get('evidence', '')}"
                    )
                else:
                    log.debug(f"Vuln {vid} excluded (severity below threshold or parse error)")
            except FuturesTimeout:
                log.error(f"Parallel fetch timed out for {vid}")
                failed += 1
            except Exception as e:
                log.error(f"Future failed for {vid}: {type(e).__name__}: {e}")
                failed += 1

    log.info(
        f"CVE scan complete — "
        f"vulns_checked={len(vuln_items)} "
        f"findings={len(cve_findings)} "
        f"failed={failed}"
    )
    # Group multiple CVEs for the same dependency into one finding
    deduplicated = _deduplicate_by_dependency(cve_findings)
    log.info(f"After deduplication: {len(deduplicated)} findings (was {len(cve_findings)})")
    return deduplicated


def _deduplicate_by_dependency(findings: list) -> list:
    """
    Groups all CVEs for the same dependency into a single finding.
    Uses the most severe CVE as the headline, lists others in the evidence.
    Without this, log4j 2.14.1 with 7 CVEs produces 7 identical-looking
    findings — noisy and unhelpful on the PR. One finding per dep is cleaner.
    """
    if not findings:
        return []

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    # Group by dep coordinates (everything before " → CVE-xxx")
    groups: dict[str, list] = {}
    for f in findings:
        dep_key = f.get("evidence", "").split(" → ")[0].strip()
        if not dep_key:
            dep_key = f.get("finding_id", "unknown")
        groups.setdefault(dep_key, []).append(f)

    merged = []
    for dep_key, dep_findings in groups.items():
        # Sort — most critical first
        dep_findings.sort(
            key=lambda x: severity_order.get(x.get("severity", "LOW"), 9)
        )
        primary = dict(dep_findings[0])  # copy the worst finding

        if len(dep_findings) > 1:
            other_cves = [
                f.get("cve_id", f.get("osv_id", "?"))
                for f in dep_findings[1:]
            ]
            shown = other_cves[:4]
            extra = len(other_cves) - 4
            extra_str = f" (+{extra} more)" if extra > 0 else ""
            primary["evidence"] = (
                f"{dep_key} → {primary.get('cve_id', primary.get('osv_id', '?'))} "
                f"(+{len(other_cves)} more CVEs: {', '.join(shown)}{extra_str})"
            )
            primary["remediation"] = (
                f"{primary['remediation']} "
                f"This dependency has {len(dep_findings)} known CVEs total."
            )
            log.info(
                f"Merged {len(dep_findings)} CVEs for {dep_key} → "
                f"primary={primary.get('cve_id')} severity={primary.get('severity')}"
            )

        merged.append(primary)

    return merged


# ── Per-vuln fetch + build (runs inside thread pool) ─────────────────────────

def _fetch_and_build(vuln_id: str, dep: dict) -> dict | None:
    """
    Fetches full vuln details from OSV and converts to a finding.
    Runs in a worker thread — must be fully self-contained.
    """
    try:
        url = OSV_VULN_URL.format(vuln_id=vuln_id)
        resp = httpx.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        full_data = resp.json()
        log.debug(f"Fetched {vuln_id}: keys={list(full_data.keys())}")
    except httpx.TimeoutException:
        log.warning(f"Timeout fetching {vuln_id}")
        return None
    except httpx.HTTPStatusError as e:
        log.warning(f"HTTP {e.response.status_code} fetching {vuln_id}")
        return None
    except Exception as e:
        log.warning(f"Failed to fetch {vuln_id}: {type(e).__name__}: {e}")
        return None

    return _build_finding(full_data, dep)


def _build_finding(vuln: dict, dep: dict) -> dict | None:
    """
    Converts a full OSV vulnerability record into our finding format.

    Severity strategy (in priority order):
      1. database_specific.severity  (most reliable — GitHub Advisory label)
      2. Numeric score from severity array (CVSS v2/v3 numeric entries)
      3. Infer from CVSS v3/v4 vector AV:N + worst-case impact metrics
      4. Default to MEDIUM if OSV included it at all (they don't include LOW by default)
    """
    vuln_id = vuln.get("id", "UNKNOWN")
    summary  = vuln.get("summary", "No description available.")
    aliases  = vuln.get("aliases", [])
    db       = vuln.get("database_specific", {})
    sev_list = vuln.get("severity", [])

    # Prefer CVE alias over GHSA ID for display
    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

    # ── Determine severity ────────────────────────────────────────────────────

    # Priority 1: database_specific.severity (e.g. "HIGH", "MODERATE", "CRITICAL")
    osv_label = db.get("severity", "").strip().upper()

    # Priority 2: try to parse a numeric score from severity array
    numeric_score = _parse_numeric_cvss(sev_list)

    # Priority 3: derive severity from label OR numeric score
    if osv_label in SEVERITY_MAP:
        severity = SEVERITY_MAP[osv_label]
        log.debug(f"{vuln_id}: severity from OSV label '{osv_label}' → {severity}")
    elif numeric_score is not None:
        if numeric_score >= 9.0:
            severity = "CRITICAL"
        elif numeric_score >= 7.0:
            severity = "HIGH"
        elif numeric_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        log.debug(f"{vuln_id}: severity from CVSS score {numeric_score} → {severity}")
    else:
        # OSV included this vulnerability at all → at least MEDIUM
        # OSV filters out clearly low-severity issues from its database
        severity = "MEDIUM"
        log.debug(f"{vuln_id}: no severity data — defaulting to MEDIUM")

    # Exclude LOW severity findings
    if severity == "LOW":
        log.debug(f"{vuln_id}: excluded (LOW severity)")
        return None

    version_display = dep['version'] or '(parent-managed)'
    dep_coords = f"{dep['group_id']}:{dep['artifact_id']}:{version_display}"
    # Use the actual pom.xml path from the dep record if available,
    # otherwise fall back to generic name. Set line=0 so findings
    # cleanly route to PR thread comment (not inline), since CVE line
    # numbers reference the full file — not the diff context GitHub needs.
    pom_path = dep.get("pom_path", "pom.xml")

    # Deps with a known version get high confidence (exact match against OSV).
    # Parent-managed deps without a version get lower confidence because OSV
    # returns ALL vulns for the package — the actual version in use (from
    # the parent BOM) may not be affected.
    version_source = dep.get("version_source", "explicit")
    if dep.get("version"):
        confidence = 0.97   # exact version match — factual
    else:
        confidence = 0.75   # no version — may be false positive

    # Add a note for parent-managed deps so reviewers know the version
    # needs manual verification
    version_note = ""
    if not dep.get("version"):
        version_note = " (version managed by parent POM — verify actual version)"

    return {
        "finding_id":  f"cve_{cve_id.replace('-', '_').replace(':', '_').lower()}",
        "severity":    severity,
        "type":        "VULN_DEPENDENCY",
        "file":        pom_path,
        "line":        dep.get("line_number", 0),       # Use the actual line number of the dependency in pom.xml
        "evidence":    f"{dep_coords} → {cve_id}{version_note}",
        "confidence":  confidence,
        "policy_ref":  "SEC-005",
        "remediation": (
            f"Upgrade {dep['artifact_id']} to a patched version. "
            f"See https://osv.dev/vulnerability/{vuln_id} for fixed versions."
        ),
        # Extra metadata passed to LLM prompt as confirmed facts
        "cve_id":     cve_id,
        "osv_id":     vuln_id,
        "cvss_score": numeric_score or 0.0,
        "summary":    summary[:300],
    }


def _parse_numeric_cvss(sev_list: list) -> float | None:
    """
    Attempts to extract a numeric CVSS score from the severity array.
    Handles:
      - Entries where score is already a float string: "8.1"
      - CVSS v3 vectors with embedded BaseScore: CVSS:3.1/.../BaseScore:9.8
    Returns None if no numeric score can be extracted (e.g. CVSS v4 vectors).
    """
    for sev in sev_list:
        score_raw = str(sev.get("score", ""))

        # Direct numeric
        try:
            val = float(score_raw)
            if 0.0 <= val <= 10.0:
                return val
        except (ValueError, TypeError):
            pass

        # BaseScore embedded in vector (CVSS v2/v3)
        m = re.search(r'BaseScore[:/](\d+\.?\d*)', score_raw, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass

        # CVSS v3 AV metric heuristic (last resort)
        # If network-accessible (AV:N) + critical impact → treat as HIGH
        # Note: CVSS v4 has AV: too but different structure

    return None
