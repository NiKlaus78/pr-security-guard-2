package com.security.guard.creds;

public class PaymentService {

    // Hardcoded secrets - security guard should catch these
    private static final String API_KEY = "zlive-xK9mP2qR4nL8vT7wY3uA";
    private static final String DB_PASS = "MyBank@Prod2024!";

    public void processPayment(String accountId) {
        // SQL injection vulnerability
        String query = "SELECT * FROM accounts WHERE id = " + accountId;
    }
}