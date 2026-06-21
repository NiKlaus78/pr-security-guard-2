package com.security.guard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Individual finding returned by the agent.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentFinding {

    @JsonProperty("finding_id")
    private String findingId;

    private String severity;

    private String type;

    private String file;

    private Integer line;

    private String evidence;

    private String remediation;

    @JsonProperty("policy_ref")
    private String policyRef;

    @JsonProperty("initial_confidence")
    private Double initialConfidence;

    @JsonProperty("final_confidence")
    private Double finalConfidence;

    @JsonProperty("critique_verdict")
    private String critiqueVerdict;

    @JsonProperty("critique_rationale")
    private String critiqueRationale;

    @JsonProperty("gate_action")
    private String gateAction;
}
