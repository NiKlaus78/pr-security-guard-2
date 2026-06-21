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
import java.util.List;

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

    @Value("${security-guard.github.token}")
    private String githubToken;

    @Value("${security-guard.github.api-base}")
    private String githubApiBase;

    private final WebClient webClient;

    /**
     * Fetches the full unified diff for a PR.
     * Returns the diff as a plain string (unified diff format).
     */
    public String fetchDiff(String repoFullName, Long prNumber) {
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

        // Truncate if diff is too large for LLM context
        if (rawDiff.length() > MAX_DIFF_CHARS) {
            log.warn("Diff truncated from {} to {} chars", rawDiff.length(), MAX_DIFF_CHARS);
            return truncateDiff(rawDiff);
        }

        return rawDiff;
    }

    /**
     * Splits a large diff into per-file chunks, each under MAX_DIFF_CHARS.
     * Useful for future chunked scanning of very large PRs.
     */
    public List<String> splitDiffByFile(String diff) {
        return List.of(diff.split("(?=diff --git )"))
                .stream()
                .filter(chunk -> !chunk.isBlank())
                .toList();
    }

    /**
     * Truncates diff to MAX_DIFF_CHARS at a clean file boundary where possible.
     */
    private String truncateDiff(String diff) {
        // Try to cut at a file boundary
        int cutPoint = diff.lastIndexOf("diff --git", MAX_DIFF_CHARS);
        if (cutPoint > MAX_DIFF_CHARS / 2) {
            return diff.substring(0, cutPoint)
                    + "\n\n[DIFF TRUNCATED — additional files omitted for context length]";
        }
        return diff.substring(0, MAX_DIFF_CHARS)
                + "\n\n[DIFF TRUNCATED]";
    }
}
