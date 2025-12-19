#!/bin/bash

# Define the base directory for Java source files
BASE="src/main/java/com/example/demo"

# List of all files to be created
FILES=(
    "$BASE/config/OpenApiConfig.java"
    "$BASE/config/SecurityConfig.java"
    "$BASE/dto/LoginRequest.java"
    "$BASE/dto/RegisterRequest.java"
    "$BASE/dto/AuthResponse.java"
    "$BASE/exception/BadRequestException.java"
    "$BASE/exception/ConflictException.java"
    "$BASE/exception/GlobalExceptionHandler.java"
    "$BASE/model/User.java"
    "$BASE/model/Category.java"
    "$BASE/model/TransactionLog.java"
    "$BASE/model/BudgetPlan.java"
    "$BASE/model/BudgetSummary.java"
    "$BASE/repository/UserRepository.java"
    "$BASE/repository/CategoryRepository.java"
    "$BASE/repository/TransactionLogRepository.java"
    "$BASE/repository/BudgetPlanRepository.java"
    "$BASE/repository/BudgetSummaryRepository.java"
    "$BASE/security/CustomUserDetailsService.java"
    "$BASE/security/JwtAuthenticationFilter.java"
    "$BASE/security/JwtTokenProvider.java"
    "$BASE/service/UserService.java"
    "$BASE/service/CategoryService.java"
    "$BASE/service/TransactionService.java"
    "$BASE/service/BudgetPlanService.java"
    "$BASE/service/BudgetSummaryService.java"
    "$BASE/service/impl/UserServiceImpl.java"
    "$BASE/service/impl/CategoryServiceImpl.java"
    "$BASE/service/impl/TransactionServiceImpl.java"
    "$BASE/service/impl/BudgetPlanServiceImpl.java"
    "$BASE/service/impl/BudgetSummaryServiceImpl.java"
    "$BASE/servlet/SimpleHelloServlet.java"
    "$BASE/DemoApplication.java"
    "src/main/resources/application.properties"
)

# Loop through the list and create files only if they don't exist
for file in "${FILES[@]}"; do
    if [ ! -f "$file" ]; then
        touch "$file"
        echo "CREATED: $file"
    else
        echo "EXISTS:  $file"
    fi
done

echo "Done! Structure is ready."