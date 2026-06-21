package com.security.guard.controller;

import com.security.guard.model.FindingDTO;
import com.security.guard.model.SecurityFinding;
import com.security.guard.service.SecurityFindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Exposes real scan findings as JSON for the live HTML dashboard
 * (dashboard.html) to poll.
 */
@RestController
@RequestMapping("/api/findings")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")  // dev only — restrict to your dashboard's origin in production
public class FindingsController {

    private final SecurityFindingRepository repository;

    /**
     * Returns the most recent scan's findings + summary stats.
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboard() {
        List<SecurityFinding> recent = repository.findTop50ByOrderByCreatedAtDesc();

        if (recent.isEmpty()) {
            return ResponseEntity.ok(Map.of("status", "no_scans_yet"));
        }

        SecurityFinding latest = recent.get(0);
        List<SecurityFinding> prFindings = repository.findByRepoFullNameAndPrNumber(
                latest.getRepoFullName(), latest.getPrNumber());

        List<FindingDTO> dtos = prFindings.stream()
                .map(FindingDTO::fromEntity)
                .collect(Collectors.toList());

        long blocked = prFindings.stream()
                .filter(f -> f.getGateAction() == SecurityFinding.GateAction.BLOCK).count();
        long warned = prFindings.stream()
                .filter(f -> f.getGateAction() == SecurityFinding.GateAction.WARN).count();
        long falsePositives = prFindings.stream()
                .filter(f -> "FALSE_POSITIVE".equals(f.getCritiqueVerdict())).count();

        String gateDecision = blocked > 0 ? "BLOCK" : (warned > 0 ? "WARN" : "ALLOW");

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "pr_number", latest.getPrNumber(),
                "repo", latest.getRepoFullName(),
                "scanned_at", latest.getCreatedAt().toString(),
                "gate_decision", gateDecision,
                "findings", dtos,
                "stats", Map.of(
                        "total", prFindings.size(),
                        "blocked", blocked,
                        "warned", warned,
                        "false_positives", falsePositives
                )
        ));
    }
}
