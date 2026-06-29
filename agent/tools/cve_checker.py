"""
CVE Checker Tool — v4

Two-step OSV lookup with Spring Boot BOM version resolution.

Key improvements over v3:
  - Resolves Spring Boot parent-managed dependency versions from Maven Central BOM
    so jackson-databind, postgresql, hibernate etc. get their REAL version checked
  - Actual line numbers restored (line=0 was a workaround no longer needed)
  - Parallel vuln detail fetching (ThreadPoolExecutor)
  - Deduplication: multiple CVEs per dependency → one consolidated finding
"""

import re
import logging
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

log = logging.getLogger(__name__)

OSV_BATCH_URL    = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL     = "https://api.osv.dev/v1/vulns/{vuln_id}"
MAVEN_BOM_URL    = (
    "https://repo1.maven.org/maven2/org/springframework/boot/"
    "spring-boot-dependencies/{version}/"
    "spring-boot-dependencies-{version}.pom"
)
REQUEST_TIMEOUT  = 12
BOM_TIMEOUT      = 20          # BOM file is large (~6MB) — needs more time
PARALLEL_WORKERS = 5
MAX_VULNS        = 30

ACTIONABLE_SEVERITIES = {"CRITICAL", "HIGH", "MODERATE", "MEDIUM"}
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}

# Mapping of common Spring Boot starters to their core transitive dependencies.
# This allows scanning transitive Spring libraries without fully resolving Maven dependency trees.
STARTER_TRANSITIVE_MAP = {
    "spring-boot-starter-web": [
        ("org.springframework", "spring-web"),
        ("org.springframework", "spring-webmvc"),
    ],
    "spring-boot-starter-security": [
        ("org.springframework.security", "spring-security-web"),
        ("org.springframework.security", "spring-security-config"),
        ("org.springframework.security", "spring-security-core"),
    ],
    "spring-boot-starter-data-jpa": [
        ("org.hibernate.orm", "hibernate-core"),
    ],
    "spring-boot-starter-webflux": [
        ("org.springframework", "spring-webflux"),
        ("io.projectreactor", "reactor-core"),
    ],
}

# ── pom.xml regex patterns ─────────────────────────────────────────────────────

GROUP_RE    = re.compile(r'<groupId>\s*([^<]+?)\s*</groupId>')
ARTIFACT_RE = re.compile(r'<artifactId>\s*([^<]+?)\s*</artifactId>')
VERSION_RE  = re.compile(r'<version>\s*([^<]+?)\s*</version>')
DEP_BLOCK   = re.compile(r'<dependency>(.*?)</dependency>', re.DOTALL | re.IGNORECASE)
PROP_TAG    = re.compile(r'<([^/>\s][^>]*)>\s*([^<]+?)\s*</\1>')
PARENT_VER  = re.compile(
    r'<parent>.*?<groupId>org\.springframework\.boot</groupId>.*?'
    r'<version>\s*([^<]+?)\s*</version>.*?</parent>',
    re.DOTALL
)


# ── Spring Boot BOM Resolution ─────────────────────────────────────────────────

def resolve_spring_boot_bom_versions(pom_content: str) -> dict[str, str]:
    """
    Detects the Spring Boot parent version in pom.xml and fetches the
    Spring Boot BOM from Maven Central to get managed dependency versions.

    Returns {groupId:artifactId → resolved_version} for all BOM-managed deps.
    """
    # Find spring-boot-starter-parent version
    parent_match = PARENT_VER.search(pom_content)
    if not parent_match:
        return {}

    sb_version = parent_match.group(1).strip()
    log.info(f"Spring Boot version detected: {sb_version} — fetching BOM...")

    bom_url = MAVEN_BOM_URL.format(version=sb_version)
    try:
        resp = httpx.get(bom_url, timeout=BOM_TIMEOUT)
        resp.raise_for_status()
        bom_xml = resp.text
        log.info(f"Spring Boot {sb_version} BOM fetched ({len(bom_xml)} chars)")
    except Exception as e:
        log.warning(f"Could not fetch Spring Boot BOM: {e} — parent-managed versions unresolvable")
        return {}

    # Step 1: Extract BOM properties (version variables like ${jackson.version})
    bom_props: dict[str, str] = {}
    props_block = re.search(r'<properties>(.*?)</properties>', bom_xml, re.DOTALL)
    if props_block:
        for m in PROP_TAG.finditer(props_block.group(1)):
            bom_props[m.group(1).strip()] = m.group(2).strip()
    log.debug(f"BOM properties: {len(bom_props)} entries")

    # Step 2: Extract dependencyManagement versions
    versions: dict[str, str] = {}
    dm_block = re.search(
        r'<dependencyManagement>\s*<dependencies>(.*?)</dependencies>\s*</dependencyManagement>',
        bom_xml, re.DOTALL
    )
    if not dm_block:
        log.warning("No <dependencyManagement> found in Spring Boot BOM")
        return {}

    for dep in DEP_BLOCK.finditer(dm_block.group(1)):
        block = dep.group(1)
        g = GROUP_RE.search(block)
        a = ARTIFACT_RE.search(block)
        v = VERSION_RE.search(block)
        if not (g and a and v):
            continue

        raw_ver = v.group(1).strip()

        # Resolve ${property} reference using BOM properties
        if raw_ver.startswith('${') and raw_ver.endswith('}'):
            prop_key = raw_ver[2:-1]
            raw_ver = bom_props.get(prop_key, raw_ver)

        # Skip still-unresolved
        if raw_ver.startswith('$'):
            continue

        key = f"{g.group(1).strip()}:{a.group(1).strip()}"
        versions[key] = raw_ver

    log.info(f"Spring Boot {sb_version} BOM: resolved {len(versions)} managed dependency versions")
    return versions


def _resolve_fallback_group_version(group_id: str, bom_versions: dict[str, str]) -> str | None:
    """
    Attempts to resolve the version of a dependency by matching its groupId
    against known imported BOMs in the Spring Boot BOM.
    """
    # 1. Jackson
    if group_id.startswith("com.fasterxml.jackson"):
        return bom_versions.get("com.fasterxml.jackson:jackson-bom")

    # 2. Spring Security
    if group_id.startswith("org.springframework.security"):
        return bom_versions.get("org.springframework.security:spring-security-bom")

    # 3. Spring Data
    if group_id.startswith("org.springframework.data"):
        return bom_versions.get("org.springframework.data:spring-data-bom")

    # 4. Spring Framework (general)
    if group_id.startswith("org.springframework"):
        if ".boot" in group_id:
            # spring-boot-starter-parent version is not in spring-framework-bom
            return None
        return bom_versions.get("org.springframework:spring-framework-bom")

    # 5. Netty
    if group_id.startswith("io.netty"):
        return bom_versions.get("io.netty:netty-bom")

    # 6. Project Reactor
    if group_id.startswith("io.projectreactor"):
        return bom_versions.get("io.projectreactor:reactor-bom")

    # 7. Micrometer
    if group_id.startswith("io.micrometer"):
        return bom_versions.get("io.micrometer:micrometer-bom")

    # 8. JUnit
    if group_id.startswith("org.junit"):
        return bom_versions.get("org.junit:junit-bom")

    return None


# ── Dependency Extraction ──────────────────────────────────────────────────────

def extract_dependencies_from_full_pom(pom_content: str) -> list[dict]:
    """
    Extracts ALL Maven dependencies from full pom.xml content.

    For dependencies without explicit <version> (BOM-managed), resolves
    the actual version from the Spring Boot BOM fetched from Maven Central.
    This is the key fix for catching jackson-databind, postgresql etc.
    """
    # Step 1: Build local property map
    local_props: dict[str, str] = {}
    props_block = re.search(r'<properties>(.*?)</properties>', pom_content, re.DOTALL)
    if props_block:
        for m in PROP_TAG.finditer(props_block.group(1)):
            local_props[m.group(1).strip()] = m.group(2).strip()

    # Step 2: Fetch Spring Boot BOM versions for parent-managed deps
    bom_versions = resolve_spring_boot_bom_versions(pom_content)

    # Step 3: Extract all <dependency> blocks
    dependencies = []

    for match in DEP_BLOCK.finditer(pom_content):
        block = match.group(1)

        g = GROUP_RE.search(block)
        a = ARTIFACT_RE.search(block)
        v = VERSION_RE.search(block)

        if not (g and a):
            continue

        group_id    = g.group(1).strip()
        artifact_id = a.group(1).strip()

        # Determine version
        if v:
            raw_ver = v.group(1).strip()
            # Resolve local property reference
            if raw_ver.startswith('${') and raw_ver.endswith('}'):
                prop_key = raw_ver[2:-1]
                raw_ver = local_props.get(prop_key, raw_ver)
            if raw_ver.startswith('$'):
                continue  # Still unresolved — skip
            version = raw_ver
            version_source = "explicit"
        else:
            # No explicit version — try BOM lookup
            bom_key = f"{group_id}:{artifact_id}"
            bom_ver = bom_versions.get(bom_key)
            if not bom_ver:
                bom_ver = _resolve_fallback_group_version(group_id, bom_versions)
            if not bom_ver:
                log.debug(f"No version found for {bom_key} — skipping")
                continue
            version = bom_ver
            version_source = "bom"

        line_num = pom_content[:match.start()].count('\n') + 1

        dependencies.append({
            "group_id":       group_id,
            "artifact_id":    artifact_id,
            "version":        version,
            "version_source": version_source,
            "line_number":    line_num
        })

    # Step 4: Expand starters with their core transitive dependencies
    expanded_dependencies = []
    for dep in dependencies:
        expanded_dependencies.append(dep)
        art_id = dep["artifact_id"]
        if art_id in STARTER_TRANSITIVE_MAP:
            for trans_g, trans_a in STARTER_TRANSITIVE_MAP[art_id]:
                # Skip duplicate entries
                if any(d["group_id"] == trans_g and d["artifact_id"] == trans_a for d in dependencies):
                    continue
                # Resolve version
                trans_key = f"{trans_g}:{trans_a}"
                trans_ver = bom_versions.get(trans_key)
                if not trans_ver:
                    trans_ver = _resolve_fallback_group_version(trans_g, bom_versions)
                
                if trans_ver:
                    expanded_dependencies.append({
                        "group_id":       trans_g,
                        "artifact_id":    trans_a,
                        "version":        trans_ver,
                        "version_source": f"transitive_from_{art_id}",
                        "line_number":    dep["line_number"],  # map to the line of the starter
                    })
                    log.debug(f"  Expanded transitive: {trans_g}:{trans_a}:{trans_ver} from {art_id}")

    dependencies = expanded_dependencies

    log.info(f"Extracted {len(dependencies)} dependencies from pom.xml "
             f"({sum(1 for d in dependencies if d['version_source'] == 'bom')} BOM-resolved, "
             f"{sum(1 for d in dependencies if d['version_source'].startswith('transitive'))} transitive)")

    for d in dependencies:
        log.debug(f"  {d['group_id']}:{d['artifact_id']}:{d['version']} [{d['version_source']}]")

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
            if g and a and v:
                ver = v.group(1).strip()
                if not ver.startswith('$'):
                    dependencies.append({
                        "group_id":       g.group(1).strip(),
                        "artifact_id":    a.group(1).strip(),
                        "version":        ver,
                        "version_source": "diff",
                        "line_number":    0
                    })
    log.info(f"Extracted {len(dependencies)} dependencies from diff (fallback)")
    return dependencies


# ── OSV API — Two-Step Lookup with Parallel Fetching ──────────────────────────

def check_dependencies_for_cves(dependencies: list[dict]) -> list[dict]:
    """
    Step 1: OSV batch query → get vulnerability IDs per dependency
    Step 2: Parallel fetch full details → extract severity + CVE alias
    Returns deduplicated list (one finding per dependency, not per CVE).
    """
    if not dependencies:
        return []

    log.info(f"OSV batch query for {len(dependencies)} dependencies...")

    queries = [
        {
            "version": dep["version"],
            "package": {
                "name":      f"{dep['group_id']}:{dep['artifact_id']}",
                "ecosystem": "Maven"
            }
        }
        for dep in dependencies
    ]

    try:
        resp = httpx.post(OSV_BATCH_URL, json={"queries": queries}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
    except httpx.TimeoutException:
        log.error("OSV batch query timed out")
        return []
    except Exception as e:
        log.error(f"OSV batch query failed: {type(e).__name__}: {e}")
        return []

    # Map vuln_id → dep
    vuln_to_dep: dict[str, dict] = {}
    for dep, result in zip(dependencies, batch_results):
        dep_key = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"
        vulns = result.get("vulns", [])
        log.info(f"  {dep_key} [{dep['version_source']}] → {len(vulns)} vulns")
        for v in vulns:
            vid = v.get("id", "")
            if vid and vid not in vuln_to_dep:
                vuln_to_dep[vid] = dep

    if not vuln_to_dep:
        log.info("No vulnerabilities found for any dependency")
        return []

    total_ids = len(vuln_to_dep)
    log.info(f"Found {total_ids} unique vuln IDs — fetching full details in parallel...")

    vuln_items = list(vuln_to_dep.items())[:MAX_VULNS]
    if total_ids > MAX_VULNS:
        log.warning(f"Capped at {MAX_VULNS} (had {total_ids})")

    # Parallel fetch
    cve_findings = []
    failed = 0

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
        future_map = {
            pool.submit(_fetch_and_build, vid, dep): vid
            for vid, dep in vuln_items
        }
        for future in as_completed(future_map, timeout=45):
            vid = future_map[future]
            try:
                finding = future.result()
                if finding:
                    cve_findings.append(finding)
                    log.info(
                        f"CVE included: {finding['cve_id']} "
                        f"severity={finding['severity']} "
                        f"for {finding.get('evidence', '')[:80]}"
                    )
                else:
                    log.debug(f"Vuln {vid} excluded (LOW severity or parse error)")
            except FuturesTimeout:
                log.error(f"Timeout fetching {vid}")
                failed += 1
            except Exception as e:
                log.error(f"Future failed for {vid}: {type(e).__name__}: {e}")
                failed += 1

    log.info(f"CVE scan complete — vulns_checked={len(vuln_items)} findings={len(cve_findings)} failed={failed}")

    deduplicated = _deduplicate_by_dependency(cve_findings)
    log.info(f"After deduplication: {len(deduplicated)} findings (was {len(cve_findings)})")
    return deduplicated


# ── Per-vuln fetch + build ────────────────────────────────────────────────────

def _fetch_and_build(vuln_id: str, dep: dict) -> dict | None:
    """Fetches full OSV vuln details and builds a finding. Runs in thread pool."""
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
    Uses database_specific.severity label as primary signal — more reliable
    than CVSS v4 vector strings which don't embed numeric scores.
    """
    vuln_id = vuln.get("id", "UNKNOWN")
    summary  = vuln.get("summary", "No description.")
    aliases  = vuln.get("aliases", [])
    db       = vuln.get("database_specific", {})
    sev_list = vuln.get("severity", [])

    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

    # Severity: OSV label is primary, numeric CVSS is secondary
    osv_label    = db.get("severity", "").strip().upper()
    numeric_score = _parse_numeric_cvss(sev_list)

    if osv_label in SEVERITY_MAP:
        severity = SEVERITY_MAP[osv_label]
        log.debug(f"{vuln_id}: severity from OSV label '{osv_label}' → {severity}")
    elif numeric_score is not None:
        severity = "CRITICAL" if numeric_score >= 9.0 else \
                   "HIGH"     if numeric_score >= 7.0 else \
                   "MEDIUM"   if numeric_score >= 4.0 else "LOW"
        log.debug(f"{vuln_id}: severity from CVSS {numeric_score} → {severity}")
    else:
        severity = "MEDIUM"  # OSV included it → at least medium
        log.debug(f"{vuln_id}: no severity data → defaulting to MEDIUM")

    if severity == "LOW":
        return None

    dep_coords  = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"
    version_src = dep.get("version_source", "")
    note        = " (BOM-resolved version)" if version_src == "bom" else ""

    return {
        "finding_id":  f"cve_{cve_id.replace('-', '_').replace(':', '_').lower()}",
        "severity":    severity,
        "type":        "VULN_DEPENDENCY",
        "file":        dep.get("pom_path", "pom.xml"),
        "line":        dep.get("line_number", 0),   # Real line number — PR thread posts work
        "evidence":    f"{dep_coords} → {cve_id}{note}",
        "confidence":  0.97,
        "policy_ref":  "SEC-005",
        "remediation": (
            f"Upgrade {dep['artifact_id']} to a patched version. "
            f"See https://osv.dev/vulnerability/{vuln_id} for fixed versions."
        ),
        "cve_id":     cve_id,
        "osv_id":     vuln_id,
        "cvss_score": numeric_score or 0.0,
        "summary":    summary[:300],
    }


def _parse_numeric_cvss(sev_list: list) -> float | None:
    """Extracts numeric CVSS score from severity array if present."""
    for sev in sev_list:
        score_raw = str(sev.get("score", ""))
        try:
            val = float(score_raw)
            if 0.0 <= val <= 10.0:
                return val
        except (ValueError, TypeError):
            pass
        m = re.search(r'BaseScore[:/](\d+\.?\d*)', score_raw, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


# ── Deduplication ─────────────────────────────────────────────────────────────

def _deduplicate_by_dependency(findings: list) -> list:
    """
    Groups multiple CVEs for the same dependency into one finding.
    Uses the most severe CVE as headline, lists the rest in evidence.
    Prevents log4j showing 7 separate PR comments for 7 CVEs.
    """
    if not findings:
        return []

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    groups: dict[str, list] = {}
    for f in findings:
        dep_key = f.get("evidence", "").split(" →")[0].strip()
        if not dep_key:
            dep_key = f.get("finding_id", "unknown")
        groups.setdefault(dep_key, []).append(f)

    merged = []
    for dep_key, dep_findings in groups.items():
        dep_findings.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 9))
        primary = dict(dep_findings[0])

        if len(dep_findings) > 1:
            other_cves = [f.get("cve_id", f.get("osv_id", "?")) for f in dep_findings[1:]]
            shown      = other_cves[:4]
            extra      = len(other_cves) - 4
            extra_str  = f" (+{extra} more)" if extra > 0 else ""
            primary["evidence"] = (
                f"{dep_key} → {primary.get('cve_id', '?')} "
                f"[+{len(other_cves)} more CVEs: {', '.join(shown)}{extra_str}]"
            )
            primary["remediation"] += f" This dependency has {len(dep_findings)} known CVEs."
            log.info(
                f"Merged {len(dep_findings)} CVEs for {dep_key} → "
                f"primary={primary.get('cve_id')} severity={primary.get('severity')}"
            )

        merged.append(primary)
    return merged