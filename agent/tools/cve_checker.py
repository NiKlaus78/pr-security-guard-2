"""
CVE Checker — OSV.dev API Integration

Parses dependency files from PR diffs and queries the OSV.dev vulnerability
database to find known CVEs. Returns structured vulnerability data that
the LLM analyzer can use to produce accurate VULN_DEPENDENCY findings.

Supported ecosystems:
  - Maven (pom.xml)
  - PyPI (requirements.txt, Pipfile)
  - npm (package.json)
  - Go (go.mod)
  - Gradle (build.gradle, build.gradle.kts)
  - crates.io (Cargo.toml)
"""

import re
import json
import logging
import concurrent.futures
from dataclasses import dataclass, asdict
from typing import Optional

import httpx

log = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 30  # seconds


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class ParsedDependency:
    """A dependency extracted from a diff."""
    name: str
    version: str
    ecosystem: str
    file: str
    line: int  # approximate line in the diff


@dataclass
class VulnerabilityResult:
    """A confirmed vulnerability from OSV."""
    cve_id: str
    summary: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    package_name: str
    package_version: str
    ecosystem: str
    fixed_version: Optional[str]
    aliases: list
    reference_url: str
    file: str
    line: int


# ── Dependency Parsers ────────────────────────────────────────────────────────

# Maven pom.xml: captures groupId, artifactId, version from added lines
# We look for <dependency> blocks in added lines of the diff
_MAVEN_DEP_PATTERN = re.compile(
    r'<groupId>\s*([^<]+?)\s*</groupId>.*?'
    r'<artifactId>\s*([^<]+?)\s*</artifactId>.*?'
    r'<version>\s*([^<$]+?)\s*</version>',
    re.DOTALL
)

# Single-line Maven version patterns for when groupId/artifactId/version
# appear on consecutive added lines — we'll collect them differently
_MAVEN_GROUP_RE = re.compile(r'<groupId>\s*([^<]+?)\s*</groupId>')
_MAVEN_ARTIFACT_RE = re.compile(r'<artifactId>\s*([^<]+?)\s*</artifactId>')
_MAVEN_VERSION_RE = re.compile(r'<version>\s*([^<$]+?)\s*</version>')

# Python requirements.txt: package==version or package>=version
_PYPI_PATTERN = re.compile(r'^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*[=~!><]=?\s*([0-9][0-9a-zA-Z.*_-]*)')

# npm package.json: "package-name": "version" or "^version" or "~version"
_NPM_PATTERN = re.compile(r'"([^"@][^"]*?)"\s*:\s*"[\^~>=<]*([0-9][0-9a-zA-Z.*_-]*)')

# Go go.mod: module/path vX.Y.Z
_GO_PATTERN = re.compile(r'^([a-zA-Z0-9._/-]+)\s+(v[0-9][0-9a-zA-Z.*_-]*)')

# Gradle: implementation 'group:artifact:version' or implementation "group:artifact:version"
_GRADLE_PATTERN = re.compile(
    r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*'
    r'[(\s]*["\']([^:]+):([^:]+):([^"\']+)["\']'
)

# Cargo.toml: name = "version" under [dependencies]
_CARGO_PATTERN = re.compile(r'^([a-zA-Z0-9_-]+)\s*=\s*"([0-9][0-9a-zA-Z.*_-]*)"')


def parse_dependencies_from_diff(diff_content: str) -> list[ParsedDependency]:
    """
    Extracts added/changed dependencies from a PR diff.
    Only considers added lines (starting with +, not +++).

    Returns a list of ParsedDependency objects.
    """
    deps = []
    current_file = ""
    current_file_deps_context = []  # For multi-line Maven parsing

    for line_num, line in enumerate(diff_content.split("\n"), 1):
        # Track current file from diff headers
        if line.startswith("diff --git"):
            # Flush Maven context from previous file
            if current_file_deps_context:
                deps.extend(_flush_maven_context(current_file_deps_context, current_file))
                current_file_deps_context = []

            parts = line.split(" b/")
            if len(parts) > 1:
                current_file = parts[-1].strip()
            continue

        # Only process added lines
        if not line.startswith("+") or line.startswith("+++"):
            continue

        added_content = line[1:]  # Strip the leading +

        # ── Maven pom.xml ──
        if current_file.endswith("pom.xml"):
            current_file_deps_context.append((line_num, added_content))

        # ── Python requirements.txt / Pipfile ──
        elif _is_python_dep_file(current_file):
            match = _PYPI_PATTERN.search(added_content)
            if match:
                deps.append(ParsedDependency(
                    name=match.group(1).strip(),
                    version=match.group(2).strip(),
                    ecosystem="PyPI",
                    file=current_file,
                    line=line_num
                ))

        # ── npm package.json ──
        elif current_file.endswith("package.json"):
            match = _NPM_PATTERN.search(added_content)
            if match:
                name = match.group(1).strip()
                # Skip metadata fields like "name", "version", "description"
                if name not in ("name", "version", "description", "main",
                                "scripts", "repository", "keywords", "author",
                                "license", "bugs", "homepage", "type", "engines"):
                    deps.append(ParsedDependency(
                        name=name,
                        version=match.group(2).strip(),
                        ecosystem="npm",
                        file=current_file,
                        line=line_num
                    ))

        # ── Go go.mod ──
        elif current_file.endswith("go.mod"):
            match = _GO_PATTERN.search(added_content)
            if match:
                deps.append(ParsedDependency(
                    name=match.group(1).strip(),
                    version=match.group(2).strip().lstrip("v"),
                    ecosystem="Go",
                    file=current_file,
                    line=line_num
                ))

        # ── Gradle build.gradle / build.gradle.kts ──
        elif current_file.endswith(("build.gradle", "build.gradle.kts")):
            match = _GRADLE_PATTERN.search(added_content)
            if match:
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()
                deps.append(ParsedDependency(
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    ecosystem="Maven",  # Gradle uses Maven repos
                    file=current_file,
                    line=line_num
                ))

        # ── Cargo.toml ──
        elif current_file.endswith("Cargo.toml"):
            match = _CARGO_PATTERN.search(added_content)
            if match:
                deps.append(ParsedDependency(
                    name=match.group(1).strip(),
                    version=match.group(2).strip(),
                    ecosystem="crates.io",
                    file=current_file,
                    line=line_num
                ))

    # Flush remaining Maven context
    if current_file_deps_context:
        deps.extend(_flush_maven_context(current_file_deps_context, current_file))

    log.info(f"Parsed {len(deps)} dependencies from diff")
    for d in deps:
        log.debug(f"  → {d.ecosystem}:{d.name}@{d.version} ({d.file}:{d.line})")

    return deps


def _is_python_dep_file(filename: str) -> bool:
    """Check if filename is a Python dependency file."""
    basename = filename.split("/")[-1] if "/" in filename else filename
    return basename in (
        "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
        "requirements-prod.txt", "Pipfile", "setup.cfg", "pyproject.toml"
    ) or basename.startswith("requirements")


def _flush_maven_context(context_lines: list, file: str) -> list[ParsedDependency]:
    """
    Parse Maven dependencies from collected added lines of a pom.xml.

    Maven deps span multiple lines (<groupId>, <artifactId>, <version>),
    so we collect them and parse as a block.
    """
    deps = []
    # Join all the added-line content to parse multi-line <dependency> blocks
    full_text = "\n".join(content for _, content in context_lines)

    # Build a line number lookup for attributing findings
    first_line = context_lines[0][0] if context_lines else 0

    # Try multi-line pattern first
    for match in _MAVEN_DEP_PATTERN.finditer(full_text):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip()

        # Skip property references like ${spring.version}
        if version.startswith("${"):
            continue

        deps.append(ParsedDependency(
            name=f"{group_id}:{artifact_id}",
            version=version,
            ecosystem="Maven",
            file=file,
            line=first_line
        ))

    # If multi-line didn't work, try sequential line-by-line parsing
    if not deps:
        current_group = None
        current_artifact = None
        current_line = first_line

        for line_num, content in context_lines:
            g = _MAVEN_GROUP_RE.search(content)
            a = _MAVEN_ARTIFACT_RE.search(content)
            v = _MAVEN_VERSION_RE.search(content)

            if g:
                current_group = g.group(1).strip()
                current_line = line_num
            if a:
                current_artifact = a.group(1).strip()
            if v and current_group and current_artifact:
                version = v.group(1).strip()
                if not version.startswith("${"):
                    deps.append(ParsedDependency(
                        name=f"{current_group}:{current_artifact}",
                        version=version,
                        ecosystem="Maven",
                        file=file,
                        line=current_line
                    ))
                current_group = None
                current_artifact = None

    return deps


# ── OSV API Client ────────────────────────────────────────────────────────────

def _query_osv_single(dep: ParsedDependency, client: httpx.Client) -> list[dict]:
    """Queries OSV single endpoint for a single dependency."""
    payload = {
        "package": {
            "name": dep.name,
            "ecosystem": dep.ecosystem
        },
        "version": dep.version
    }
    try:
        response = client.post(OSV_SINGLE_URL, json=payload, timeout=OSV_TIMEOUT)
        response.raise_for_status()
        return response.json().get("vulns", [])
    except Exception as e:
        log.error(f"OSV query failed for {dep.ecosystem}:{dep.name}@{dep.version}: {e}")
        return []


def query_osv_batch(
    dependencies: list[ParsedDependency],
    min_cvss: float = 7.0
) -> list[VulnerabilityResult]:
    """
    Queries the OSV.dev API for vulnerabilities in the given dependencies.
    Uses ThreadPoolExecutor to query dependencies in parallel using the single query endpoint
    to retrieve full vulnerability details.

    Args:
        dependencies: List of parsed dependencies to check
        min_cvss: Minimum CVSS score to include (from security policy)

    Returns:
        List of VulnerabilityResult for confirmed vulnerabilities
    """
    if not dependencies:
        return []

    log.info(f"Querying OSV API for {len(dependencies)} dependencies in parallel")
    vulnerabilities = []

    try:
        with httpx.Client(timeout=OSV_TIMEOUT) as client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                # Map dependencies to query tasks
                future_to_dep = {
                    executor.submit(_query_osv_single, dep, client): dep
                    for dep in dependencies
                }
                
                for future in concurrent.futures.as_completed(future_to_dep):
                    dep = future_to_dep[future]
                    try:
                        vulns = future.result()
                        for vuln in vulns:
                            vuln_result = _parse_osv_vuln(vuln, dep, min_cvss)
                            if vuln_result:
                                vulnerabilities.append(vuln_result)
                    except Exception as e:
                        log.error(f"Error retrieving OSV result for {dep.name}: {e}")

    except Exception as e:
        log.error(f"OSV scan execution failed: {e}")

    log.info(f"OSV scan complete: {len(vulnerabilities)} vulnerabilities found "
             f"(CVSS >= {min_cvss})")
    return vulnerabilities


def _parse_osv_vuln(
    vuln: dict,
    dep: ParsedDependency,
    min_cvss: float
) -> Optional[VulnerabilityResult]:
    """
    Parse a single OSV vulnerability response into a VulnerabilityResult.
    Returns None if the vulnerability doesn't meet the CVSS threshold.
    """
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", vuln.get("details", "No description available"))
    aliases = vuln.get("aliases", [])

    # Extract CVSS score from severity array
    cvss_score = _extract_cvss_score(vuln)

    # If no CVSS score found, check database_specific or default based on severity
    if cvss_score == 0.0:
        cvss_score = _estimate_cvss_from_severity(vuln)

    # Apply CVSS threshold filter
    if cvss_score < min_cvss:
        return None

    # Determine severity from CVSS
    severity = _cvss_to_severity(cvss_score)

    # Find the best CVE alias
    cve_id = vuln_id
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # Extract fixed version if available
    fixed_version = _extract_fixed_version(vuln, dep.ecosystem, dep.name)

    # Get the best reference URL
    reference_url = _extract_reference_url(vuln)

    # Truncate summary for readability
    if len(summary) > 200:
        summary = summary[:197] + "..."

    return VulnerabilityResult(
        cve_id=cve_id,
        summary=summary,
        severity=severity,
        cvss_score=cvss_score,
        package_name=dep.name,
        package_version=dep.version,
        ecosystem=dep.ecosystem,
        fixed_version=fixed_version,
        aliases=aliases[:5],  # Cap aliases for prompt size
        reference_url=reference_url,
        file=dep.file,
        line=dep.line
    )


def _extract_cvss_score(vuln: dict) -> float:
    """Extract the highest CVSS score from OSV severity entries."""
    best_score = 0.0
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # OSV can return CVSS vectors — extract numeric score
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            # Try to parse the score from the vector string
            # Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H or CVSS:4.0/...
            score = _parse_cvss_vector_score(score_str)
            if score > best_score:
                best_score = score
        # Some entries have a direct score field
        try:
            direct_score = float(score_str)
            if direct_score > best_score:
                best_score = direct_score
        except (ValueError, TypeError):
            pass

    return best_score


def _parse_cvss_vector_score(vector: str) -> float:
    """
    Estimate a CVSS score from a CVSS v3 vector string.

    This is a simplified calculation — real CVSS scoring is complex.
    We use a heuristic based on the impact metrics.
    """
    if not vector or not vector.startswith("CVSS:"):
        return 0.0

    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    # Simple heuristic scoring based on key CVSS v3 metrics
    score = 5.0  # Base

    # Attack Vector
    av = metrics.get("AV", "N")
    if av == "N":
        score += 1.5  # Network — most severe
    elif av == "A":
        score += 1.0  # Adjacent
    elif av == "L":
        score += 0.5  # Local

    # Attack Complexity
    ac = metrics.get("AC", "L")
    if ac == "L":
        score += 0.8  # Low complexity
    elif ac == "H":
        score += 0.2

    # Privileges Required
    pr = metrics.get("PR", "N")
    if pr == "N":
        score += 0.8  # No privileges needed
    elif pr == "L":
        score += 0.4

    # Impact: Confidentiality, Integrity, Availability
    for impact_key in ("C", "I", "A"):
        # For CVSS V4, check VC/VI/VA first
        impact = metrics.get(f"V{impact_key}", metrics.get(impact_key, "N"))
        if impact == "H":
            score += 0.6
        elif impact == "L":
            score += 0.2

    return min(10.0, round(score, 1))


def _estimate_cvss_from_severity(vuln: dict) -> float:
    """Estimate CVSS score when no explicit score is available."""
    # Check ecosystem-specific severity
    db_specific = vuln.get("database_specific", {})
    severity_text = db_specific.get("severity", "").upper()

    if severity_text == "CRITICAL":
        return 9.5
    elif severity_text == "HIGH":
        return 8.0
    elif severity_text == "MODERATE" or severity_text == "MEDIUM":
        return 5.5
    elif severity_text == "LOW":
        return 3.0

    # Default: assume medium if we have a vuln entry but no score
    return 5.0


def _cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _extract_fixed_version(vuln: dict, ecosystem: str, package_name: str) -> Optional[str]:
    """Extract the fixed version from the OSV affected ranges."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() == ecosystem.lower():
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


def _extract_reference_url(vuln: dict) -> str:
    """Extract the most relevant reference URL."""
    for ref in vuln.get("references", []):
        ref_type = ref.get("type", "")
        if ref_type == "ADVISORY":
            return ref.get("url", "")

    # Fall back to any reference
    refs = vuln.get("references", [])
    if refs:
        return refs[0].get("url", "")

    return f"https://osv.dev/vulnerability/{vuln.get('id', '')}"


# ── Convenience Function ─────────────────────────────────────────────────────

def scan_diff_for_vulnerabilities(
    diff_content: str,
    min_cvss: float = 7.0
) -> tuple[list[ParsedDependency], list[VulnerabilityResult]]:
    """
    Full pipeline: parse diff → extract dependencies → query OSV → return results.

    Args:
        diff_content: The unified diff string from a PR
        min_cvss: Minimum CVSS score to flag (from security policy)

    Returns:
        Tuple of (parsed_dependencies, vulnerability_results)
    """
    dependencies = parse_dependencies_from_diff(diff_content)
    if not dependencies:
        log.info("No dependency files found in diff — skipping CVE scan")
        return [], []

    vulnerabilities = query_osv_batch(dependencies, min_cvss)
    return dependencies, vulnerabilities


def vulnerability_to_finding(vuln: VulnerabilityResult) -> dict:
    """
    Convert a VulnerabilityResult to the standard finding format
    used by the LangGraph pipeline.
    """
    return {
        "finding_id": f"dep_{vuln.cve_id.replace('-', '_').lower()[:8]}",
        "severity": vuln.severity,
        "type": "VULN_DEPENDENCY",
        "file": vuln.file,
        "line": vuln.line,
        "evidence": (
            f"{vuln.package_name}@{vuln.package_version} — "
            f"{vuln.cve_id} (CVSS {vuln.cvss_score}): {vuln.summary}"
        )[:200],
        "confidence": _cvss_to_confidence(vuln.cvss_score),
        "policy_ref": "SEC-005",
        "remediation": _build_remediation(vuln),
        # Extra fields for context
        "cve_id": vuln.cve_id,
        "cvss_score": vuln.cvss_score,
        "package_name": vuln.package_name,
        "package_version": vuln.package_version,
        "fixed_version": vuln.fixed_version,
        "reference_url": vuln.reference_url
    }


def _cvss_to_confidence(cvss_score: float) -> float:
    """
    Map CVSS score to confidence level.
    CVE findings from OSV are factual, so confidence is high.
    """
    if cvss_score >= 9.0:
        return 0.98
    elif cvss_score >= 7.0:
        return 0.95
    elif cvss_score >= 4.0:
        return 0.85
    else:
        return 0.70


def _build_remediation(vuln: VulnerabilityResult) -> str:
    """Build a specific remediation string for the finding."""
    if vuln.fixed_version:
        return (
            f"Upgrade {vuln.package_name} from {vuln.package_version} "
            f"to {vuln.fixed_version} to fix {vuln.cve_id}. "
            f"Ref: {vuln.reference_url}"
        )
    return (
        f"Remove or replace {vuln.package_name}@{vuln.package_version} "
        f"({vuln.cve_id}, CVSS {vuln.cvss_score}). "
        f"No fixed version available. Ref: {vuln.reference_url}"
    )
