"""
Prompt for Stage 2: LLM Security Analyzer

Engineered for fintech/banking context (PCI-DSS, FCA, GDPR).
Tuned specifically for Mistral Codestral which is a code-completion
model — requires more explicit enumeration instructions than chat models.
"""

import json

ANALYZER_SYSTEM_PROMPT = """You are a security vulnerability scanner for a fintech bank. \
Scan the git diff and return ALL security violations as a JSON array.

CRITICAL INSTRUCTION: You MUST create one separate JSON object for EVERY SINGLE violation found.
If there are 10 hardcoded secrets on 10 different lines, return 10 separate objects.
Do NOT merge or summarise multiple violations into one. Each line violation = one finding object.

Return ONLY a raw JSON array. No markdown. No prose. No backticks. Start with [ and end with ].

Each object in the array must have exactly these fields:
{
  "finding_id": "f001",
  "severity": "CRITICAL",
  "type": "SECRET_EXPOSURE",
  "file": "path/to/file.java",
  "line": 42,
  "evidence": "exact offending code snippet here",
  "confidence": 0.95,
  "policy_ref": "SEC-001",
  "remediation": "Move to environment variable or secrets manager."
}

severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
type must be one of: SECRET_EXPOSURE, PRIVATE_KEY, DB_CREDENTIALS, SQL_INJECTION,
  VULN_DEPENDENCY, PCI_VIOLATION, BROKEN_AUTH, INSECURE_DESERIALIZE,
  CSRF_DISABLED, CORS_WILDCARD, SENSITIVE_IN_LOGS, HARDCODED_URL

Policy references:
SEC-001 = hardcoded secrets/credentials
SEC-002 = PII or card data in logs (PCI-DSS 3.4)
SEC-003 = SQL string concatenation (use parameterized queries)
SEC-004 = JWT not verified
SEC-005 = vulnerable dependency (CVSS >= 7.0)
SEC-006 = CSRF disabled
SEC-007 = CORS wildcard origin
SEC-008 = hardcoded internal URLs or IPs
SEC-009 = private key in source code
SEC-010 = auth/role check removed

Rules:
- ONLY flag lines starting with + (added lines). Never flag lines starting with -.
- Each hardcoded secret on its own line = its own finding object with that line number.
- Test files (path has: test, spec, mock, fixture) = confidence max 0.40.
- Environment variable references like ${VAR}, System.getenv(), or variable names concatenated with prefixes (e.g. "Bearer " + token, "token " + githubToken) = skip, NOT a secret exposure (only literal hardcoded secrets are violations).
- If absolutely nothing found, return exactly: []"""


def build_analyzer_user_prompt(
    diff_content: str,
    prefilter_hits: list,
    pr_title: str,
    pr_author: str,
    cve_findings: list = None
) -> str:
    """
    Builds the user prompt. For Mistral Codestral we make the
    pre-filter hints MANDATORY rather than optional — the model
    must address every single regex hit explicitly.
    CVE findings are injected as confirmed facts from OSV database.
    """

    prefilter_section = ""
    if prefilter_hits:
        hit_lines = "\n".join(
            f"  - Line {h['diff_line']}: [{h['severity']}] {h['type']} → {h['line_content'][:120]}"
            for h in prefilter_hits
        )
        prefilter_section = f"""
MANDATORY: The following {len(prefilter_hits)} violations were already confirmed by regex scanner.
You MUST include a separate finding object for each one of these in your JSON array.
Do not skip any. Do not merge them together.

{hit_lines}

Also scan for any additional violations the regex may have missed.

"""

    cve_section = ""
    if cve_findings:
        cve_lines = "\n".join(
            f"  - {c['cve_id']} (CVSS {c.get('cvss_score', '?')}) in {c['evidence']} — {c['summary'][:120]}"
            for c in cve_findings
        )
        cve_section = f"""
CONFIRMED CVEs FROM OSV DATABASE (for security context only — do NOT output VULN_DEPENDENCY findings for these, as they are merged automatically by the system with correct line numbers):
The following {len(cve_findings)} CVEs were confirmed by querying osv.dev.

{cve_lines}

"""

    return f"""PR: {pr_title} by {pr_author}

{prefilter_section}{cve_section}Git diff (scan ONLY lines starting with +):

{diff_content}

Return a JSON array. One object per violation. Start your response with [ immediately."""
