package com.example.demo.controller;

import com.example.demo.model.BudgetSummary;
import com.example.demo.service.BudgetSummaryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/budget-summaries")
public class BudgetSummaryController {

    private final BudgetSummaryService budgetSummaryService;

    public BudgetSummaryController(BudgetSummaryService budgetSummaryService) {
        this.budgetSummaryService = budgetSummaryService;
    }

    @PostMapping("/generate/{planId}")
    public ResponseEntity<BudgetSummary> generateSummary(@PathVariable Long planId) {
        return ResponseEntity.ok(budgetSummaryService.generateSummary(planId));
    }

    @GetMapping("/{planId}")
    public ResponseEntity<BudgetSummary> getSummary(@PathVariable Long planId) {
        return ResponseEntity.ok(budgetSummaryService.getSummary(planId));
    }
}
