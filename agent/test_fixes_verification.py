"""
Verification test for Fixes #1, #3, #4, #5.
Run with: agent\.venv\Scripts\python.exe agent\test_fixes_verification.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("MISTRAL_API_KEY", "test-key")

from nodes import (
    regex_prefilter_node,
    gate_decision_node,
    _correct_llm_lines,
    SECRET_TYPES,
)

passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


# ═══════════════════════════════════════════════════════════════════════════════
# Fix #1: Line-collision — three secrets on adjacent lines should each get
#         a distinct regex hit; _correct_llm_lines must not collapse them.
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(" Fix #1: Line-collision in _correct_llm_lines()")
print("="*70 + "\n")

prefilter_hits = [
    {"file": "test.js", "type": "HARDCODED_API_KEY",  "diff_line": 14, "line_content": 'const API_KEY = "abc"', "severity": "CRITICAL", "source": "regex_prefilter"},
    {"file": "test.js", "type": "HARDCODED_SECRET",   "diff_line": 15, "line_content": 'const SECRET = "xyz"', "severity": "HIGH", "source": "regex_prefilter"},
    {"file": "test.js", "type": "HARDCODED_PASSWORD",  "diff_line": 16, "line_content": 'const PASSWORD = "pw"', "severity": "CRITICAL", "source": "regex_prefilter"},
]

# Simulate LLM returning all three findings but all pointing to line 14
llm_findings = [
    {"file": "test.js", "type": "HARDCODED_API_KEY",  "line": 14, "confidence": 0.95},
    {"file": "test.js", "type": "HARDCODED_SECRET",   "line": 14, "confidence": 0.90},  # wrong line
    {"file": "test.js", "type": "HARDCODED_PASSWORD",  "line": 14, "confidence": 0.92},  # wrong line
]

corrected = _correct_llm_lines(llm_findings, prefilter_hits)
corrected_lines = [f["line"] for f in corrected]
check("Three secrets get three distinct lines",
      len(set(corrected_lines)) == 3,
      f"got lines: {corrected_lines}")
check("API_KEY stays at 14",   corrected[0]["line"] == 14)
check("SECRET corrected to 15", corrected[1]["line"] == 15)
check("PASSWORD corrected to 16", corrected[2]["line"] == 16)


# ═══════════════════════════════════════════════════════════════════════════════
# Fix #3: Confidence floor — FALSE_POSITIVE with high initial_confidence
#         and no regex backing should become WARN, not DISCARD.
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(" Fix #3: Confidence floor for non-regex-backed findings")
print("="*70 + "\n")

state_fix3 = {
    "scan_id": "test-fix3",
    "critiqued_findings": [
        {
            "finding_id": "f001",
            "type": "MISSING_AUTH_CHECK",
            "severity": "HIGH",
            "file": "app.js",
            "line": 42,
            "confidence": 0.50,        # final (after critique knocked it down)
            "initial_confidence": 0.92, # original LLM confidence
            "final_confidence": 0.50,
            "critique_verdict": "FALSE_POSITIVE",
            "critique_rationale": "Might be handled elsewhere",
        },
        {
            "finding_id": "f002",
            "type": "WEAK_HASHING",
            "severity": "MEDIUM",  # MEDIUM, not HIGH — should NOT be rescued
            "file": "utils.js",
            "line": 10,
            "confidence": 0.40,
            "initial_confidence": 0.95,
            "final_confidence": 0.40,
            "critique_verdict": "FALSE_POSITIVE",
            "critique_rationale": "Not security-sensitive context",
        },
        {
            "finding_id": "f003",
            "type": "OPEN_REDIRECT",
            "severity": "HIGH",
            "file": "routes.js",
            "line": 88,
            "confidence": 0.30,
            "initial_confidence": 0.70,  # below 0.90 — should NOT be rescued
            "final_confidence": 0.30,
            "critique_verdict": "FALSE_POSITIVE",
            "critique_rationale": "URL is validated",
        },
    ],
    "prefilter_hits": [],  # No regex backing
}

result = gate_decision_node(state_fix3)
findings_by_id = {f["finding_id"]: f for f in result["final_findings"]}

check("HIGH + initial_conf 0.92 -> WARN (rescued)",
      findings_by_id["f001"]["gate_action"] == "WARN",
      f"got: {findings_by_id['f001']['gate_action']}")
check("MEDIUM + initial_conf 0.95 -> DISCARD (severity too low)",
      findings_by_id["f002"]["gate_action"] == "DISCARD",
      f"got: {findings_by_id['f002']['gate_action']}")
check("HIGH + initial_conf 0.70 -> DISCARD (confidence too low)",
      findings_by_id["f003"]["gate_action"] == "DISCARD",
      f"got: {findings_by_id['f003']['gate_action']}")


# ═══════════════════════════════════════════════════════════════════════════════
# Fix #4: New regex patterns for ENCRYPTION_KEY, WEAK_HASHING,
#         PATH_TRAVERSAL, OPEN_REDIRECT
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(" Fix #4: New regex patterns")
print("="*70 + "\n")

FIX4_DIFF = """diff --git a/vuln.js b/vuln.js
new file mode 100644
--- /dev/null
+++ b/vuln.js
@@ -0,0 +1,12 @@
+const ENCRYPTION_KEY = "SuperSecretKey12345678";
+const hash = crypto.createHash('md5').update(data).digest('hex');
+app.get('/file', (req, res) => {
+  const userPath = req.query.path;
+  fs.readFile("./uploads/" + userPath, (err, data) => {
+    res.send(data);
+  });
+});
+app.get('/goto', (req, res) => {
+  const target = req.query.url;
+  res.redirect(target);
+});
"""

state_fix4 = {"scan_id": "test-fix4", "diff_content": FIX4_DIFF}
result = regex_prefilter_node(state_fix4)
hits = result["prefilter_hits"]
hit_types = {h["type"] for h in hits}

check("ENCRYPTION_KEY detected",   "HARDCODED_ENCRYPTION_KEY" in hit_types, f"types: {hit_types}")
check("WEAK_HASHING detected",     "WEAK_HASHING" in hit_types, f"types: {hit_types}")
check("PATH_TRAVERSAL detected (via taint lookback)",
      "PATH_TRAVERSAL" in hit_types, f"types: {hit_types}")
check("OPEN_REDIRECT detected (via taint lookback)",
      "OPEN_REDIRECT" in hit_types, f"types: {hit_types}")


# ═══════════════════════════════════════════════════════════════════════════════
# Fix #5: XSS lookback — two-step pattern detection
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(" Fix #5: XSS lookback for two-step patterns")
print("="*70 + "\n")

XSS_DIFF = """diff --git a/xss.js b/xss.js
new file mode 100644
--- /dev/null
+++ b/xss.js
@@ -0,0 +1,6 @@
+app.get('/welcome', (req, res) => {
+  const name = req.query.name;
+  const greeting = "Hello!";
+  res.send('<h1>Welcome, ' + name + '</h1>');
+});
"""

state_fix5 = {"scan_id": "test-fix5", "diff_content": XSS_DIFF}
result = regex_prefilter_node(state_fix5)
hits = result["prefilter_hits"]
xss_hits = [h for h in hits if h["type"] == "XSS_RISK"]

check("XSS two-step pattern detected", len(xss_hits) >= 1, f"xss hits: {xss_hits}")
if xss_hits:
    check("XSS on correct line (res.send line)", xss_hits[0]["diff_line"] == 4,
          f"got line: {xss_hits[0]['diff_line']}")

# Also verify direct XSS still works
XSS_DIRECT_DIFF = """diff --git a/direct.js b/direct.js
new file mode 100644
--- /dev/null
+++ b/direct.js
@@ -0,0 +1,3 @@
+app.get('/echo', (req, res) => {
+  res.send(req.query.msg);
+});
"""

state_direct = {"scan_id": "test-fix5-direct", "diff_content": XSS_DIRECT_DIFF}
result = regex_prefilter_node(state_direct)
direct_xss = [h for h in result["prefilter_hits"] if h["type"] == "XSS_RISK"]
check("Direct XSS pattern still works", len(direct_xss) >= 1, f"hits: {direct_xss}")

# ═══════════════════════════════════════════════════════════════════════════════
# Safety net: type-aware coverage — SECRET findings must not suppress
# unrelated SQL_INJECTION / COMMAND_INJECTION regex hits at nearby lines
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(" Safety net: type-aware coverage (the 'not all getting logged' fix)")
print("="*70 + "\n")

from nodes import gate_decision_node as _gate

# Simulate: LLM found SECRET_EXPOSURE at 14,17,18 (survived as BLOCK).
# Regex also found SQL_INJECTION at 23, COMMAND_INJECTION at 32, etc.
# but the LLM missed them / critique killed them / they had no regex backing.
# The safety net MUST inject them — they shouldn't be suppressed by the secrets.
state_safety = {
    "scan_id": "test-safety-net",
    "critiqued_findings": [
        # These survived critique and get BLOCK (they're regex-backed secrets)
        {"finding_id": "s1", "type": "SECRET_EXPOSURE", "severity": "CRITICAL",
         "file": "server.js", "line": 14, "confidence": 0.95,
         "initial_confidence": 0.95, "final_confidence": 0.95,
         "critique_verdict": "CONFIRMED", "critique_rationale": "Real secret"},
        {"finding_id": "s2", "type": "SECRET_EXPOSURE", "severity": "CRITICAL",
         "file": "server.js", "line": 17, "confidence": 0.92,
         "initial_confidence": 0.92, "final_confidence": 0.92,
         "critique_verdict": "CONFIRMED", "critique_rationale": "Real secret"},
        {"finding_id": "s3", "type": "SECRET_EXPOSURE", "severity": "CRITICAL",
         "file": "server.js", "line": 18, "confidence": 0.93,
         "initial_confidence": 0.93, "final_confidence": 0.93,
         "critique_verdict": "CONFIRMED", "critique_rationale": "Real secret"},
    ],
    "prefilter_hits": [
        # Secrets
        {"file": "server.js", "type": "HARDCODED_API_KEY",    "diff_line": 14, "severity": "CRITICAL", "line_content": 'const API_KEY = "abc"',                      "source": "regex_prefilter"},
        {"file": "server.js", "type": "HARDCODED_SECRET",     "diff_line": 15, "severity": "HIGH",     "line_content": 'const JWT_SECRET = "xyz"',                    "source": "regex_prefilter"},
        {"file": "server.js", "type": "HARDCODED_PASSWORD",   "diff_line": 16, "severity": "CRITICAL", "line_content": 'const DB_PASSWORD = "pw"',                    "source": "regex_prefilter"},
        {"file": "server.js", "type": "DB_CREDENTIALS_IN_URL","diff_line": 18, "severity": "CRITICAL", "line_content": 'const DB_URL = "mongodb://admin:pw@host"',    "source": "regex_prefilter"},
        # Non-secret danger patterns (far from the secrets)
        {"file": "server.js", "type": "SQL_INJECTION",        "diff_line": 23, "severity": "HIGH",     "line_content": '"SELECT * FROM x WHERE id = " + id',           "source": "regex_dangerous_call"},
        {"file": "server.js", "type": "COMMAND_INJECTION",    "diff_line": 32, "severity": "HIGH",     "line_content": "exec('cmd ' + input)",                         "source": "regex_dangerous_call"},
        {"file": "server.js", "type": "BROKEN_AUTH",          "diff_line": 40, "severity": "HIGH",     "line_content": "jwt.decode(token)",                            "source": "regex_dangerous_call"},
        {"file": "server.js", "type": "PCI_DATA_IN_LOGS",     "diff_line": 47, "severity": "HIGH",     "line_content": 'console.log("card=" + cardNumber + " cvv=")',  "source": "regex_prefilter"},
        {"file": "server.js", "type": "CORS_WILDCARD",        "diff_line": 53, "severity": "MEDIUM",   "line_content": "res.header('Access-Control-Allow-Origin','*')", "source": "regex_dangerous_call"},
        {"file": "server.js", "type": "INSECURE_RANDOM",      "diff_line": 59, "severity": "MEDIUM",   "line_content": "Math.random().toString(36)",                   "source": "regex_dangerous_call"},
    ],
}

result = _gate(state_safety)
final = result["final_findings"]
non_discard = [f for f in final if f["gate_action"] != "DISCARD"]
non_discard_types = {f["type"] for f in non_discard}
non_discard_lines = {f.get("line", f.get("diff_line", 0)) for f in non_discard}

# All danger-pattern hits must be injected by safety net (not suppressed by secrets)
check("SQL_INJECTION injected by safety net",
      "SQL_INJECTION" in non_discard_types, f"types: {non_discard_types}")
check("COMMAND_INJECTION injected by safety net",
      "COMMAND_INJECTION" in non_discard_types, f"types: {non_discard_types}")
check("BROKEN_AUTH injected by safety net",
      "BROKEN_AUTH" in non_discard_types, f"types: {non_discard_types}")
check("PCI_DATA_IN_LOGS injected by safety net",
      "PCI_DATA_IN_LOGS" in non_discard_types, f"types: {non_discard_types}")
check("CORS_WILDCARD injected by safety net",
      "CORS_WILDCARD" in non_discard_types, f"types: {non_discard_types}")
check("INSECURE_RANDOM injected by safety net",
      "INSECURE_RANDOM" in non_discard_types, f"types: {non_discard_types}")

# Adjacent secrets at lines 15 and 16 must also survive (not suppressed by line-14 secret)
check("HARDCODED_SECRET at line 15 injected",
      any(f.get("line", f.get("diff_line")) == 15 for f in non_discard),
      f"non-discard lines: {non_discard_lines}")
check("HARDCODED_PASSWORD at line 16 injected",
      any(f.get("line", f.get("diff_line")) == 16 for f in non_discard),
      f"non-discard lines: {non_discard_lines}")

print(f"\n  Total non-DISCARD findings: {len(non_discard)} (was 3 before fix, should be 11+)")


# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
total = passed + failed
if failed == 0:
    print(f" ALL {total} CHECKS PASSED")
else:
    print(f" {failed}/{total} CHECKS FAILED")
print("="*70 + "\n")

sys.exit(1 if failed else 0)
