package com.security.guard.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.HmacUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Validates GitHub webhook HMAC-SHA256 signatures.
 *
 * GitHub sends: X-Hub-Signature-256: sha256=<hex_digest>
 * We recompute using our webhook secret and compare securely.
 */
@Service
@Slf4j
public class WebhookValidationService {

    @Value("${security-guard.github.webhook-secret}")
    private String webhookSecret;

    /**
     * Returns true if the provided signature matches the HMAC-SHA256
     * of the raw payload using our webhook secret.
     *
     * Uses constant-time comparison to prevent timing attacks.
     */
    public boolean isValidSignature(String rawPayload, String signatureHeader) {
        if (signatureHeader == null || !signatureHeader.startsWith("sha256=")) {
            log.warn("Missing or malformed signature header");
            return false;
        }

        String receivedHex = signatureHeader.substring("sha256=".length());
        String computedHex = HmacUtils.hmacSha256Hex(webhookSecret, rawPayload);

        // Constant-time comparison — prevents timing attacks
        return constantTimeEquals(receivedHex, computedHex);
    }

    /**
     * Constant-time string comparison to prevent timing side-channel attacks.
     * Always iterates the full length of both strings.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
