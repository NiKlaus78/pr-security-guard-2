package com.security.guard.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class FindingDTO {
    private String severity;
    private String type;
    private String file;
    private Integer line;
    private Double initialConfidence;
    private Double finalConfidence;
    private String critiqueVerdict;
    private String gateAction;
    private String remediation;

    public static FindingDTO fromEntity(SecurityFinding f) {
        FindingDTO dto = new FindingDTO();
        dto.severity = f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM";
        dto.type = f.getFindingType();
        dto.file = f.getFilePath();
        dto.line = f.getLineNumber();
        dto.initialConfidence = f.getInitialConfidence();
        dto.finalConfidence = f.getFinalConfidence();
        dto.critiqueVerdict = f.getCritiqueVerdict();
        dto.gateAction = f.getGateAction() != null ? f.getGateAction().name() : "DISCARD";
        dto.remediation = f.getRemediation();
        return dto;
    }
}
