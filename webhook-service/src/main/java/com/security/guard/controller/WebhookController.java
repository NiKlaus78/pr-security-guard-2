package com.security.guard.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.guard.model.GitHubPrPayload;
import com.security.guard.service.WebhookValidationService;
import com.security.guard.service.PrScanOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

/**
 * Receives GitHub webhook events for pull_request actions.
 *
 * Flow:
 *  1. Validate HMAC-SHA256 signature (GitHub sends X-Hub-Signature-256)
 *  2. Filter: only process PR open/sync/reopen events
 *  3. Dispatch async scan — return 200 immediately so GitHub doesn't retry
 *  4. PrScanOrchestrator handles everything else
 */
@RestController
@RequestMapping("/webhook")
@RequiredArgsConstructor
@Slf4j
public class WebhookController {

    private static final Set<String> SCAN_ACTIONS =
            Set.of("opened", "synchronize", "reopened");

    private final WebhookValidationService validationService;
    private final PrScanOrchestrator scanOrchestrator;
    private final ObjectMapper objectMapper;

    /**
     * Main webhook endpoint. GitHub must be configured to send pull_request events here.
     */
    @PostMapping("/github")
    public ResponseEntity<Map<String, String>> handleGitHubWebhook(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", defaultValue = "unknown") String eventType,
            @RequestHeader(value = "X-GitHub-Delivery", defaultValue = "unknown") String deliveryId,
            @RequestBody String rawPayload) {

        log.info("Webhook received | event={} delivery={}", eventType, deliveryId);

        // ── Step 1: Validate HMAC signature ──────────────────────────────
        if (!validationService.isValidSignature(rawPayload, signature)) {
            log.warn("Invalid webhook signature | delivery={}", deliveryId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid signature"));
        }

        // ── Step 2: Only process pull_request events ──────────────────────
        if (!"pull_request".equals(eventType)) {
            log.debug("Skipping non-PR event: {}", eventType);
            return ResponseEntity.ok(Map.of("status", "skipped", "reason", "not a PR event"));
        }

        // ── Step 3: Parse payload ──────────────────────────────────────────
        GitHubPrPayload payload;
        try {
            payload = objectMapper.readValue(rawPayload, GitHubPrPayload.class);
        } catch (Exception e) {
            log.error("Failed to parse PR payload | delivery={}", deliveryId, e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid payload format"));
        }

        // ── Step 4: Filter by action ───────────────────────────────────────
        String action = payload.getAction();
        if (!SCAN_ACTIONS.contains(action)) {
            log.debug("Skipping PR action: {}", action);
            return ResponseEntity.ok(Map.of("status", "skipped", "reason", "action=" + action));
        }

        log.info("Triggering security scan | repo={} PR=#{} action={}",
                payload.getRepository().getFullName(),
                payload.getPullRequest().getNumber(),
                action);

        // ── Step 5: Dispatch async scan (returns immediately) ─────────────
        scanOrchestrator.triggerScanAsync(payload);

        return ResponseEntity.ok(Map.of(
                "status", "accepted",
                "pr", String.valueOf(payload.getPullRequest().getNumber()),
                "message", "Security scan queued"
        ));
    }

    /**
     * Health check endpoint for K8s liveness probe.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "pr-security-guard"));
    }
}
