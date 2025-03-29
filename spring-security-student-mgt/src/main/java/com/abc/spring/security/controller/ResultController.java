package com.abc.spring.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/results")
public class ResultController {

    // Create Result (Only Admin)
    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> createResult() {
        return ResponseEntity.ok("Result created successfully.");
    }

    // Get All Results (Admin & Moderator)
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','MODERATOR')")
    public ResponseEntity<String> getAllResults() {
        return ResponseEntity.ok("List of all results.");
    }

    // Get Result by ID (Admin, Moderator, or the Student who owns the result)
    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN','MODERATOR') or ( hasRole('STUDENT') and #userId == authentication.principal.userId)")
    public ResponseEntity<String> getResultByUserId(@PathVariable Long userId, Authentication authentication) {
        return ResponseEntity.ok("Result for user: " + userId);
    }

    // Update Result by ID (Only Admin & Moderator)
    @PutMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN','MODERATOR')")
    public ResponseEntity<String> updateResult(@PathVariable Long userId) {
        return ResponseEntity.ok("Result updated for user: " + userId);
    }

    // Delete Result by ID (Only Admin)
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<String> deleteResult(@PathVariable Long userId) {
        return ResponseEntity.ok("Result deleted for user: " + userId);
    }

}
