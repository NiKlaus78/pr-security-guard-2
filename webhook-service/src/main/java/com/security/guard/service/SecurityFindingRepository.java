package com.security.guard.service;

import com.security.guard.model.SecurityFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityFindingRepository extends JpaRepository<SecurityFinding, Long> {

    List<SecurityFinding> findByRepoFullNameAndPrNumber(String repoFullName, Long prNumber);

    List<SecurityFinding> findByRepoFullNameAndHeadSha(String repoFullName, String headSha);

    List<SecurityFinding> findTop50ByOrderByCreatedAtDesc();

    @Query("SELECT f FROM SecurityFinding f WHERE f.repoFullName = :repo " +
           "AND f.gateAction = 'BLOCK' ORDER BY f.createdAt DESC")
    List<SecurityFinding> findBlockedFindingsByRepo(String repo);

    @Query("SELECT COUNT(f) FROM SecurityFinding f WHERE f.critiqueVerdict = 'FALSE_POSITIVE'")
    long countFalsePositives();
}
