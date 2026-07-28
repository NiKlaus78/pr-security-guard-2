package com.security.guard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ObjectInputStream;
import org.apache.logging.log4j.LogManager;

/**
 * TEST FILE — covers all 16 security violation types
 * for PR Security Guard verification
 */
public class UltimateSecurityTest {

    // ── CRITICAL: Hardcoded Secrets ──────────────────────────────────────────
    private static final String API_KEY = "xK9mP2qR4nL8vT7wY3uA";
    private static final String OPENAI_KEY = "skproj-T3BlbkFJabc123def456";
    private static final String AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String DB_PASSWORD = "MyBank@Prod2024!";
    private static final String GIT_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ";
    private static final String DB_URL = "jdbc:postgresql://admin:prodpass123@prod.lloyds.com:5432/accounts";
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_5NjK4t3FHH0";

    // ── HIGH: SQL Injection ───────────────────────────────────────────────────
    public void getAccount(String accountId) {
        String query = "SELECT * FROM accounts WHERE id = " + accountId;
        String query2 = "SELECT * FROM users WHERE name = '" + accountId + "'";
    }

    // ── HIGH: Insecure Deserialization ────────────────────────────────────────
    // Use a plain InputStream here to avoid a compile-time dependency on the
    // servlet API (javax.servlet) inside this test file.
    public Object deserialize(java.io.InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // ── HIGH: Broken Auth — JWT not verified ──────────────────────────────────
    public void processToken(String token) {
        // Parsing without signature verification
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
    }

    // ── MEDIUM: PCI Violation — card data in logs ─────────────────────────────
    public void logPayment(String cardNumber, String cvv, String ssn) {
        System.out.println("Processing card: " + cardNumber + " CVV: " + cvv);
        System.out.println("Customer SSN: " + ssn);
    }

    // ── MEDIUM: Sensitive data in logs ────────────────────────────────────────
    public void logAuth(String password, String token) {
        System.out.println("User password: " + password);
        System.out.println("Bearer token: " + token);
    }

    // ── MEDIUM: Hardcoded internal URLs ───────────────────────────────────────
    private static final String PROD_DB = "http://internal-prod-db.lloyds.internal:5432";
    private static final String PROD_API = "http://10.0.0.45:8080/payments/internal";

}