package com.example.demo.controller;

import com.example.demo.model.BudgetPlan;
import com.example.demo.model.User;
import com.example.demo.service.BudgetPlanService;
import com.example.demo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/budget-plans")
public class BudgetPlanController {

    private final BudgetPlanService budgetPlanService;
    private final UserService userService;

    public BudgetPlanController(BudgetPlanService budgetPlanService, UserService userService) {
        this.budgetPlanService = budgetPlanService;
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<BudgetPlan> createBudgetPlan(@RequestBody BudgetPlan plan, Authentication authentication) {
        User user = userService.findByEmail(authentication.getName());
        return ResponseEntity.ok(budgetPlanService.createBudgetPlan(user.getId(), plan));
    }

    @GetMapping
    public ResponseEntity<BudgetPlan> getBudgetPlan(@RequestParam Integer month, @RequestParam Integer year, Authentication authentication) {
        User user = userService.findByEmail(authentication.getName());
        return ResponseEntity.ok(budgetPlanService.getBudgetPlan(user.getId(), month, year));
    }
}
