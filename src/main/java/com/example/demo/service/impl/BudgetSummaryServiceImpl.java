package com.example.demo.service.impl;

import com.example.demo.exception.BadRequestException;
import com.example.demo.model.BudgetPlan;
import com.example.demo.model.BudgetSummary;
import com.example.demo.model.Category;
import com.example.demo.model.TransactionLog;
import com.example.demo.repository.BudgetPlanRepository;
import com.example.demo.repository.BudgetSummaryRepository;
import com.example.demo.repository.TransactionLogRepository;
import com.example.demo.service.BudgetSummaryService;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class BudgetSummaryServiceImpl implements BudgetSummaryService {

    private final BudgetSummaryRepository budgetSummaryRepository;
    private final BudgetPlanRepository budgetPlanRepository;
    private final TransactionLogRepository transactionLogRepository;

    public BudgetSummaryServiceImpl(BudgetSummaryRepository budgetSummaryRepository,
                                    BudgetPlanRepository budgetPlanRepository,
                                    TransactionLogRepository transactionLogRepository) {
        this.budgetSummaryRepository = budgetSummaryRepository;
        this.budgetPlanRepository = budgetPlanRepository;
        this.transactionLogRepository = transactionLogRepository;
    }

    @Override
    public BudgetSummary generateSummary(Long budgetPlanId) {
        BudgetPlan plan = budgetPlanRepository.findById(budgetPlanId)
                .orElseThrow(() -> new BadRequestException("Budget Plan not found"));

        LocalDate start = LocalDate.of(plan.getYear(), plan.getMonth(), 1);
        LocalDate end = start.withDayOfMonth(start.lengthOfMonth());

        List<TransactionLog> logs = transactionLogRepository.findByUserAndTransactionDateBetween(plan.getUser(), start, end);

        double totalIncome = logs.stream()
                .filter(l -> Category.TYPE_INCOME.equals(l.getCategory().getType()))
                .mapToDouble(TransactionLog::getAmount)
                .sum();

        double totalExpense = logs.stream()
                .filter(l -> Category.TYPE_EXPENSE.equals(l.getCategory().getType()))
                .mapToDouble(TransactionLog::getAmount)
                .sum();

        BudgetSummary summary = budgetSummaryRepository.findByBudgetPlan(plan)
                .orElse(new BudgetSummary());

        summary.setBudgetPlan(plan);
        summary.setTotalIncome(totalIncome);
        summary.setTotalExpense(totalExpense);
        summary.setStatus(totalExpense > plan.getExpenseLimit() ? BudgetSummary.STATUS_OVER_LIMIT : BudgetSummary.STATUS_UNDER_LIMIT);
        
        // If it's a new entity, generatedAt will be set by @PrePersist. 
        // If updating, we might want to update the timestamp or leave it?
        // Spec says: "Lifecycle method onCreate() initializes generatedAt when the entity is first persisted."
        // It doesn't explicitly say to update it on re-generation. 
        // But usually "generate" implies fresh data. I will explicitly set it to now if it's an update, or let @PrePersist handle it for new.
        // Actually, @PrePersist only runs on persist (insert). 
        // I will set it manually to ensure it reflects the latest generation time.
        summary.setGeneratedAt(LocalDateTime.now());

        return budgetSummaryRepository.save(summary);
    }

    @Override
    public BudgetSummary getSummary(Long budgetPlanId) {
        BudgetPlan plan = budgetPlanRepository.findById(budgetPlanId)
                .orElseThrow(() -> new BadRequestException("Budget Plan not found"));
        return budgetSummaryRepository.findByBudgetPlan(plan)
                .orElseThrow(() -> new BadRequestException("Summary not found"));
    }
}
