"""
Verification test: feeds a simulated unified diff of server.js through
regex_prefilter_node and checks line numbers + detection coverage.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Minimal stub to avoid needing the full LangChain/Mistral stack
os.environ.setdefault("MISTRAL_API_KEY", "test-key")

from nodes import regex_prefilter_node

# Simulated unified diff for server.js (all lines are added = new file)
SAMPLE_DIFF = """diff --git a/server.js b/server.js
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/server.js
@@ -0,0 +1,68 @@
+/**
+ * Sample Node.js Payment Service
+ * Intentionally contains security vulnerabilities to test PR Security Guard.
+ * DO NOT use this code in production.
+ */
+
+const express = require('express');
+const jwt = require('jsonwebtoken');
+const { exec } = require('child_process');
+const app = express();
+app.use(express.json());
+
+// ── CRITICAL: Hardcoded secrets ────────────────────────────────────────────
+const API_KEY = "mK8pQ2rT5vW9xZ3aB6cD1eF4gH7jL0nP";
+const JWT_SECRET = "MySecretKey123!ProdBanking";
+const DB_PASSWORD = "Lloyds@PaymentDB2024";
+
+const DB_URL = "mongodb://admin:SuperSecret123@prod-db.internal:27017/payments";
+
+// ── HIGH: SQL injection via string concatenation ───────────────────────────
+app.get('/account/:id', (req, res) => {
+  const accountId = req.params.id;
+  const query = "SELECT * FROM accounts WHERE id = " + accountId;
+  db.query(query, (err, result) => {
+    res.json(result);
+  });
+});
+
+// ── HIGH: Command injection ─────────────────────────────────────────────────
+app.post('/generate-report', (req, res) => {
+  const filename = req.body.filename;
+  exec('generate-report ' + filename, (err, stdout) => {
+    res.send(stdout);
+  });
+});
+
+// ── HIGH: JWT not properly verified ─────────────────────────────────────────
+app.post('/verify-token', (req, res) => {
+  const token = req.headers.authorization;
+  const decoded = jwt.decode(token);  // decode() does NOT verify signature!
+  res.json({ user: decoded });
+});
+
+// ── MEDIUM: Sensitive data in logs ──────────────────────────────────────────
+app.post('/process-payment', (req, res) => {
+  const { cardNumber, cvv, amount } = req.body;
+  console.log("Processing payment: card=" + cardNumber + " cvv=" + cvv + " amount=" + amount);
+  res.json({ status: "processed" });
+});
+
+// ── MEDIUM: CORS wildcard ───────────────────────────────────────────────────
+app.use((req, res, next) => {
+  res.header('Access-Control-Allow-Origin', '*');
+  next();
+});
+
+// ── MEDIUM: Insecure randomness for security tokens ─────────────────────────
+function generateResetToken() {
+  return Math.random().toString(36).substring(2);
+}
+
+// ── HIGH: XSS — unescaped user input rendered directly ──────────────────────
+app.get('/welcome', (req, res) => {
+  const name = req.query.name;
+  res.send('<h1>Welcome, ' + name + '</h1>');
+});
+
+app.listen(3000, () => console.log('Payment service running on port 3000'));
"""

# Expected findings with their actual source file line numbers
EXPECTED = {
    14: "HARDCODED_API_KEY",
    15: "HARDCODED_SECRET",       # JWT_SECRET matches "secret" pattern
    16: "HARDCODED_PASSWORD",
    18: "DB_CREDENTIALS_IN_URL",
    23: "SQL_INJECTION",
    32: "COMMAND_INJECTION",
    40: "BROKEN_AUTH",
    47: "PCI_DATA_IN_LOGS",
    53: "CORS_WILDCARD",
    59: "INSECURE_RANDOM",
    65: "XSS_RISK",
}


def main():
    state = {
        "scan_id": "test-001",
        "diff_content": SAMPLE_DIFF,
    }

    result = regex_prefilter_node(state)
    hits = result["prefilter_hits"]

    print(f"\n{'='*70}")
    print(f" Regex Pre-filter Results: {len(hits)} hits found")
    print(f"{'='*70}\n")

    # Map hits by line for quick lookup
    hits_by_line = {}
    for h in hits:
        line = h["diff_line"]
        hits_by_line.setdefault(line, []).append(h)

    print(f"{'Line':>5}  {'Type':<25}  {'Severity':<10}  {'File':<15}  Evidence (first 60 chars)")
    print(f"{'-'*5}  {'-'*25}  {'-'*10}  {'-'*15}  {'-'*40}")
    for h in sorted(hits, key=lambda x: x["diff_line"]):
        print(f"{h['diff_line']:>5}  {h['type']:<25}  {h['severity']:<10}  {h['file']:<15}  {h['line_content'][:60]}")

    # Validate
    print(f"\n{'='*70}")
    print(f" Validation")
    print(f"{'='*70}\n")

    all_pass = True

    for expected_line, expected_type in sorted(EXPECTED.items()):
        found = hits_by_line.get(expected_line, [])
        type_match = any(h["type"] == expected_type for h in found)
        status = "PASS" if type_match else "FAIL"
        if not type_match:
            all_pass = False
            actual = ", ".join(f"{h['type']}@{h['diff_line']}" for h in hits if expected_type in h["type"] or h["diff_line"] == expected_line) or "NOT FOUND"
            print(f"  {status}  Line {expected_line}: expected {expected_type}, actual: {actual}")
        else:
            print(f"  {status}  Line {expected_line}: {expected_type}")

    # Check for unexpected hits (not necessarily failures, just informational)
    expected_lines = set(EXPECTED.keys())
    unexpected = [h for h in hits if h["diff_line"] not in expected_lines]
    if unexpected:
        print(f"\n  Additional findings (not in expected list):")
        for h in unexpected:
            print(f"       Line {h['diff_line']}: {h['type']} ({h['severity']})")

    print(f"\n{'='*70}")
    if all_pass:
        print(f" ALL {len(EXPECTED)} EXPECTED FINDINGS VERIFIED CORRECTLY")
    else:
        print(f" SOME CHECKS FAILED - see above")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
