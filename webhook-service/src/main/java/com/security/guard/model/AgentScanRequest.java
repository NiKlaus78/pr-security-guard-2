package com.security.guard.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request sent to the Python LangGraph agent service.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AgentScanRequest {

    @JsonProperty("pr_number")
    private Long prNumber;

    @JsonProperty("repo_full_name")
    private String repoFullName;

    @JsonProperty("head_sha")
    private String headSha;

    @JsonProperty("base_sha")
    private String baseSha;

    @JsonProperty("pr_author")
    private String prAuthor;

    @JsonProperty("pr_title")
    private String prTitle;

    @JsonProperty("diff_content")
    private String diffContent;

    @JsonProperty("pom_xml_content")
    private String pomXmlContent;    // Full pom.xml content when changed in PR
}
