package com.security.guard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * Represents the GitHub webhook payload for a pull_request event.
 * Only maps fields we actually need — GitHub sends ~150 fields total.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class GitHubPrPayload {

    private String action;          // "opened", "synchronize", "reopened"

    @JsonProperty("pull_request")
    private PullRequest pullRequest;

    private Repository repository;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PullRequest {
        private Long number;
        private String title;
        private String state;

        @JsonProperty("html_url")
        private String htmlUrl;

        @JsonProperty("diff_url")
        private String diffUrl;

        @JsonProperty("patch_url")
        private String patchUrl;

        private Head head;
        private Base base;
        private User user;

        @JsonProperty("additions")
        private Integer additions;

        @JsonProperty("deletions")
        private Integer deletions;

        @JsonProperty("changed_files")
        private Integer changedFiles;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Head {
        private String sha;
        private String ref;          // branch name
        private Repository repo;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Base {
        private String sha;
        private String ref;          // base branch (e.g. "main")
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Repository {
        @JsonProperty("full_name")
        private String fullName;     // e.g. "lloyds/payment-service"

        @JsonProperty("clone_url")
        private String cloneUrl;

        private String name;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class User {
        private String login;
        private String email;
    }
}
