package com.security.guard.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Fetches the unified diff for a GitHub PR using the GitHub API.
 *
 * Two strategies:
 *  1. Primary: GET /repos/{owner}/{repo}/pulls/{pr_number} with Accept: application/vnd.github.diff
 *  2. Fallback: Use the diff_url from the webhook payload
 *
 * Diffs are chunked if they exceed the LLM context limit (we target ~50k chars).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DiffExtractorService {

    private static final int MAX_DIFF_CHARS = 50_000;
    private static final int TIMEOUT_SECONDS = 30;

    // File extensions / paths considered LOW priority for security scanning.
    // These are deprioritized when truncation is needed.
    private static final Set<String> LOW_PRIORITY_EXTENSIONS = Set.of(
        ".html", ".css", ".md", ".txt", ".svg", ".png", ".jpg", ".gif",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
        ".lock", ".min.js", ".min.css"
    );

    @Value("${security-guard.github.token}")
    private String githubToken;

    @Value("${security-guard.github.api-base}")
    private String githubApiBase;

    private final WebClient webClient;

    /**
     * Fetches the full unified diff for a PR, WITH smart truncation applied.
     * Returns the diff as a plain string (unified diff format).
     */
    public String fetchDiff(String repoFullName, Long prNumber) {
        String rawDiff = fetchRawDiff(repoFullName, prNumber);

        if (rawDiff.length() > MAX_DIFF_CHARS) {
            log.warn("Diff truncated from {} to ~{} chars", rawDiff.length(), MAX_DIFF_CHARS);
            return smartTruncateDiff(rawDiff);
        }

        return rawDiff;
    }

    /**
     * Fetches the FULL untruncated unified diff for a PR.
     * Used by the orchestrator to detect manifest paths BEFORE truncation,
     * so that pom.xml / package.json / requirements.txt are never lost.
     */
    public String fetchRawDiff(String repoFullName, Long prNumber) {
        log.debug("Fetching diff | repo={} PR=#{}", repoFullName, prNumber);

        String url = String.format("%s/repos/%s/pulls/%d", githubApiBase, repoFullName, prNumber);

        String rawDiff = webClient.get()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                .header(HttpHeaders.ACCEPT, "application/vnd.github.diff")
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .onErrorResume(e -> {
                    log.error("Failed to fetch diff | repo={} PR=#{}", repoFullName, prNumber, e);
                    return Mono.just("");
                })
                .block();

        if (rawDiff == null || rawDiff.isBlank()) {
            log.warn("Empty diff received | repo={} PR=#{}", repoFullName, prNumber);
            return "";
        }

        log.info("Diff fetched | repo={} PR=#{} size={}chars", repoFullName, prNumber, rawDiff.length());
        return rawDiff;
    }

    /**
     * Splits a large diff into per-file chunks, each under MAX_DIFF_CHARS.
     * Useful for future chunked scanning of very large PRs.
     */
    public List<String> splitDiffByFile(String diff) {
        return List.of(diff.split("(?m)^(?=diff --git )"))
                .stream()
                .filter(chunk -> !chunk.isBlank())
                .toList();
    }

    /**
     * Fetches the full raw content of a file from GitHub at a specific commit.
     * Used to get the complete pom.xml when it appears in a PR diff —
     * so CVE scanning covers ALL dependencies, not just newly added lines.
     */
    public String fetchFileContent(String repoFullName, String filePath, String ref) {
        String url = String.format("%s/repos/%s/contents/%s?ref=%s",
                githubApiBase, repoFullName, filePath, ref);

        try {
            String response = webClient.get()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github.raw+json")
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .block();

            log.info("Fetched full file | repo={} file={} ref={}",
                    repoFullName, filePath, ref);
            return response != null ? response : "";

        } catch (Exception e) {
            log.warn("Could not fetch full file | repo={} file={} error={}",
                    repoFullName, filePath, e.getMessage());
            return "";
        }
    }

    /**
     * Smart truncation: splits the diff into per-file chunks, prioritizes
     * security-relevant source files (Java, Python, JS, XML manifests) over
     * low-priority files (HTML presentations, CSS, images, lock files, etc.).
     *
     * Strategy:
     *   1. Split diff into per-file chunks
     *   2. Classify each chunk as HIGH or LOW priority
     *   3. Include ALL high-priority chunks first (up to budget)
     *   4. Fill remaining budget with low-priority chunks
     *   5. If still over budget, hard-truncate at a file boundary
     */
    public String smartTruncateDiff(String diff) {
        List<String> fileChunks = splitDiffByFile(diff);

        List<String> highPriority = new ArrayList<>();
        List<String> lowPriority = new ArrayList<>();

        for (String chunk : fileChunks) {
            if (isLowPriority(chunk)) {
                lowPriority.add(chunk);
            } else {
                highPriority.add(chunk);
            }
        }

        log.info("Smart truncation: {} high-priority files, {} low-priority files",
                highPriority.size(), lowPriority.size());

        StringBuilder result = new StringBuilder();
        int budget = MAX_DIFF_CHARS;

        // Phase 1: Include all high-priority file chunks
        for (String chunk : highPriority) {
            if (result.length() + chunk.length() <= budget) {
                result.append(chunk);
            } else {
                // Even a high-priority chunk that's too large: include what fits
                int remaining = budget - result.length();
                if (remaining > 200) {
                    result.append(chunk, 0, remaining);
                    result.append("\n\n[FILE TRUNCATED — remainder omitted for context length]\n");
                }
                break;
            }
        }

        // Phase 2: Fill remaining budget with low-priority chunks
        for (String chunk : lowPriority) {
            if (result.length() + chunk.length() <= budget) {
                result.append(chunk);
            }
            // Skip low-priority chunks that don't fit
        }

        if (result.length() < diff.length()) {
            int omitted = fileChunks.size() - (int) fileChunks.stream()
                    .filter(c -> result.toString().contains(c.substring(0, Math.min(80, c.length()))))
                    .count();
            if (omitted > 0) {
                result.append(String.format(
                    "\n\n[DIFF TRUNCATED — %d low-priority file(s) omitted for context length]", omitted));
            }
        }

        return result.toString();
    }

    /**
     * Determines if a diff chunk is low-priority for security scanning.
     * Extracts the file path from the "diff --git a/path b/path" header.
     */
    private boolean isLowPriority(String chunk) {
        // Extract file path from first line: "diff --git a/path/file b/path/file"
        String firstLine = chunk.split("\n", 2)[0];
        String filePath = firstLine.toLowerCase();

        // Deprioritize the security guard tool's own source code to avoid budget starvation
        if (filePath.contains("agent/") || 
            filePath.contains("webhook-service/src/main/java/com/security/guard/service/") ||
            filePath.contains("webhook-service/src/main/java/com/security/guard/controller/") ||
            filePath.contains("webhook-service/src/main/java/com/security/guard/config/") ||
            filePath.contains("webhook-service/src/main/java/com/security/guard/model/") ||
            filePath.contains(".gitignore") ||
            filePath.contains("docker-compose") ||
            filePath.contains("pr-security-guard-presentation")) {
            return true;
        }

        // Check against low-priority extensions
        for (String ext : LOW_PRIORITY_EXTENSIONS) {
            if (filePath.endsWith(ext)) {
                return true;
            }
        }

        // Presentation files, documentation, generated files
        if (filePath.contains("presentation") || filePath.contains("readme")
                || filePath.contains("changelog") || filePath.contains("license")
                || filePath.contains(".github/") || filePath.contains("docs/")) {
            return true;
        }

        return false;
    }
}
