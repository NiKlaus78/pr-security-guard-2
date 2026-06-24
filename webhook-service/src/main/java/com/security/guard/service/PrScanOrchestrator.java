package com.security.guard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.guard.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates the full PR security scan pipeline.
 *
 * Runs asynchronously so the webhook controller can return 200 immediately.
 *
 * Steps:
 *  1. Fetch PR diff from GitHub
 *  2. Send diff to Python LangGraph agent for analysis
 *  3. Parse agent findings
 *  4. Post review comments to GitHub PR
 *  5. Set GitHub commit status (success/failure)
 *  6. Persist findings to PostgreSQL audit log
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrScanOrchestrator {

    @Value("${security-guard.agent.service-url}")
    private String agentServiceUrl;

    @Value("${security-guard.agent.timeout-seconds:120}")
    private int agentTimeoutSeconds;

    @Value("${security-guard.thresholds.block-merge-confidence:0.85}")
    private double blockMergeConfidence;

    private final DiffExtractorService diffExtractorService;
    private final GitHubCommentService commentService;
    private final SecurityFindingRepository findingRepository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    /**
     * Entry point called by WebhookController. Runs in a separate thread pool.
     */
    @Async
    public void triggerScanAsync(GitHubPrPayload payload) {
        String repoFullName = payload.getRepository().getFullName();
        Long prNumber = payload.getPullRequest().getNumber();
        String headSha = payload.getPullRequest().getHead().getSha();

        log.info("=== Starting security scan | repo={} PR=#{} ===", repoFullName, prNumber);

        try {
            // ── Step 1: Set pending status on GitHub commit ────────────────
            commentService.setPendingStatus(repoFullName, headSha,
                    "PR Security Guard is scanning...");

            // ── Step 2: Fetch unified diff ─────────────────────────────────
            String diffContent = diffExtractorService.fetchDiff(repoFullName, prNumber);

            if (diffContent.isBlank()) {
                log.warn("No diff content found | repo={} PR=#{}", repoFullName, prNumber);
                commentService.setSuccessStatus(repoFullName, headSha, "No diff to scan.");
                return;
            }

            // ── Step 3: Build agent scan request ──────────────────────────
            // Fetch full pom.xml content if it appears in the diff.
            // Extract the ACTUAL path from the diff header — don't assume root-level pom.xml.
            // e.g. diff could show "webhook-service/pom.xml" not just "pom.xml"
            String pomXmlContent = "";
            String pomXmlPath = extractPomXmlPath(diffContent);
            if (pomXmlPath != null) {
                log.info("pom.xml detected at '{}' — fetching full file for CVE scan | repo={} PR=#{}",
                        pomXmlPath, repoFullName, prNumber);
                pomXmlContent = diffExtractorService.fetchFileContent(
                        repoFullName, pomXmlPath, headSha);
            }

            AgentScanRequest request = AgentScanRequest.builder()
                    .prNumber(prNumber)
                    .repoFullName(repoFullName)
                    .headSha(headSha)
                    .baseSha(payload.getPullRequest().getBase().getSha())
                    .prAuthor(payload.getPullRequest().getUser().getLogin())
                    .prTitle(payload.getPullRequest().getTitle())
                    .diffContent(diffContent)
                    .pomXmlContent(pomXmlContent)
                    .build();

            // ── Step 4: Call Python LangGraph agent ────────────────────────
            log.info("Calling agent service | repo={} PR=#{}", repoFullName, prNumber);
            String agentResponseJson = callAgentService(request);

            // ── Step 5: Parse response ─────────────────────────────────────
            JsonNode response = objectMapper.readTree(agentResponseJson);
            String gateDecision = response.path("gate_decision").asText("ALLOW");
            String langsmithRunId = response.path("langsmith_run_id").asText("");
            JsonNode findings = response.path("findings");

            log.info("Agent scan complete | repo={} PR=#{} decision={} findings={}",
                    repoFullName, prNumber, gateDecision, findings.size());

            // ── Step 6: Post PR review comments ───────────────────────────
            List<SecurityFinding> persistedFindings = new ArrayList<>();
            for (JsonNode finding : findings) {
                String gateAction = finding.path("gate_action").asText("DISCARD");

                if (!"DISCARD".equals(gateAction)) {
                    // Post inline comment on the PR
                    commentService.postFindingComment(
                            repoFullName, prNumber, headSha, finding);
                }

                // Persist everything including discarded findings (for eval)
                SecurityFinding entity = buildFindingEntity(
                        finding, repoFullName, prNumber,
                        payload.getPullRequest().getUser().getLogin(),
                        headSha, langsmithRunId);
                persistedFindings.add(entity);
            }

            findingRepository.saveAll(persistedFindings);

            // ── Step 7: Set final GitHub commit status ─────────────────────
            if ("BLOCK".equals(gateDecision)) {
                long criticalCount = countBySeverity(findings, "CRITICAL");
                long highCount = countBySeverity(findings, "HIGH");
                String description = String.format(
                        "BLOCKED: %d critical, %d high severity findings.",
                        criticalCount, highCount);
                commentService.setFailureStatus(repoFullName, headSha, description);

                // Also post a summary comment on the PR thread
                commentService.postSummaryComment(repoFullName, prNumber, findings, gateDecision);

            } else if ("WARN".equals(gateDecision)) {
                commentService.setWarningStatus(repoFullName, headSha,
                        "Security warnings found. Review required.");
                commentService.postSummaryComment(repoFullName, prNumber, findings, gateDecision);

            } else {
                commentService.setSuccessStatus(repoFullName, headSha,
                        "No security violations detected.");
            }

            log.info("=== Scan complete | repo={} PR=#{} decision={} ===",
                    repoFullName, prNumber, gateDecision);

        } catch (Exception e) {
            log.error("Scan failed | repo={} PR=#{}", repoFullName, prNumber, e);
            commentService.setFailureStatus(repoFullName, headSha,
                    "Security scan failed. Check guard service logs.");
        }
    }

    /**
     * Calls the Python FastAPI agent service with the scan request.
     */
    private String callAgentService(AgentScanRequest request) throws Exception {
        String requestJson = objectMapper.writeValueAsString(request);

        return webClient.post()
                .uri(agentServiceUrl + "/scan")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .bodyValue(requestJson)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(agentTimeoutSeconds))
                .block();
    }

    private long countBySeverity(JsonNode findings, String severity) {
        long count = 0;
        for (JsonNode f : findings) {
            if (severity.equals(f.path("severity").asText()) &&
                !"DISCARD".equals(f.path("gate_action").asText())) {
                count++;
            }
        }
        return count;
    }

    private SecurityFinding buildFindingEntity(
            JsonNode f, String repo, Long prNumber, String author,
            String headSha, String langsmithRunId) {

        return SecurityFinding.builder()
                .repoFullName(repo)
                .prNumber(prNumber)
                .prAuthor(author)
                .headSha(headSha)
                .findingId(f.path("finding_id").asText())
                .severity(parseSeverity(f.path("severity").asText()))
                .findingType(f.path("type").asText())
                .filePath(f.path("file").asText())
                .lineNumber(f.path("line").asInt(0))
                .evidence(f.path("evidence").asText())
                .remediation(f.path("remediation").asText())
                .policyRef(f.path("policy_ref").asText())
                .initialConfidence(f.path("initial_confidence").asDouble())
                .finalConfidence(f.path("final_confidence").asDouble())
                .critiqueVerdict(f.path("critique_verdict").asText())
                .critiqueRationale(f.path("critique_rationale").asText())
                .gateAction(parseGateAction(f.path("gate_action").asText()))
                .langsmithRunId(langsmithRunId)
                .build();
    }

    private SecurityFinding.Severity parseSeverity(String s) {
        try { return SecurityFinding.Severity.valueOf(s); }
        catch (Exception e) { return SecurityFinding.Severity.MEDIUM; }
    }

    private SecurityFinding.GateAction parseGateAction(String s) {
        try { return SecurityFinding.GateAction.valueOf(s); }
        catch (Exception e) { return SecurityFinding.GateAction.DISCARD; }
    }

    /**
     * Extracts the actual pom.xml file path from a unified diff.
     * Handles cases where pom.xml is in a subdirectory (e.g. webhook-service/pom.xml).
     *
     * Looks for lines like:
     *   diff --git a/webhook-service/pom.xml b/webhook-service/pom.xml
     */
    private String extractPomXmlPath(String diffContent) {
        for (String line : diffContent.split("\n")) {
            if (line.startsWith("diff --git") && line.contains("pom.xml")) {
                // Format: "diff --git a/path/pom.xml b/path/pom.xml"
                // Extract the b/ path (the new version)
                String[] parts = line.split(" ");
                for (String part : parts) {
                    if (part.startsWith("b/") && part.endsWith("pom.xml")) {
                        return part.substring(2); // Strip the "b/" prefix
                    }
                }
            }
        }
        return null;
    }
}
