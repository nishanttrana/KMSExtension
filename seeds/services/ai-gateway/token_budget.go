package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// BudgetCheckResult holds the outcome of a budget check.
type BudgetCheckResult struct {
	Allowed        bool    `json:"allowed"`
	RemainingTokens int64  `json:"remaining_tokens"`
	RemainingCost  float64 `json:"remaining_cost_usd"`
	UsedPct        float64 `json:"used_pct"`
	Warning        bool    `json:"warning"`
	WarningMessage string  `json:"warning_message,omitempty"`
	DenyReason     string  `json:"deny_reason,omitempty"`
}

// BudgetAlert is published when a budget threshold is reached.
type BudgetAlert struct {
	TenantID  string  `json:"tenant_id"`
	Scope     string  `json:"scope"`
	ScopeID   string  `json:"scope_id"`
	UsedPct   float64 `json:"used_pct"`
	UsedTokens int64  `json:"used_tokens"`
	MaxTokens  int64  `json:"max_tokens"`
	CostUsed  float64 `json:"cost_used_usd"`
	MaxCost   float64 `json:"max_cost_usd"`
	Period    string  `json:"period"`
	Timestamp time.Time `json:"timestamp"`
}

// BudgetAlertFunc is a callback for publishing budget alerts (e.g., via NATS).
type BudgetAlertFunc func(alert BudgetAlert)

// BudgetStore is the persistence interface for token budgets.
type BudgetStore interface {
	GetBudgets(ctx context.Context, tenantID string) ([]TokenBudget, error)
	GetBudget(ctx context.Context, budgetID string) (TokenBudget, error)
	GetBudgetsByScope(ctx context.Context, tenantID, scope, scopeID string) ([]TokenBudget, error)
	UpdateBudgetUsage(ctx context.Context, budgetID string, usedTokens int64, costUsed float64) error
	ResetBudget(ctx context.Context, budgetID string, newResetAt time.Time) error
	ListExpiredBudgets(ctx context.Context, now time.Time) ([]TokenBudget, error)
}

// BudgetManager manages token budgets with in-memory caching and persistent storage.
type BudgetManager struct {
	store      BudgetStore
	mu         sync.RWMutex
	cache      map[string]*TokenBudget // keyed by budget ID
	alertFn    BudgetAlertFunc
	logger     *log.Logger
	stopCh     chan struct{}
	cacheTTL   time.Duration
	cacheTime  map[string]time.Time // when each cache entry was last refreshed
}

// BudgetManagerConfig holds configuration for the BudgetManager.
type BudgetManagerConfig struct {
	Store      BudgetStore
	AlertFn    BudgetAlertFunc
	Logger     *log.Logger
	CacheTTL   time.Duration
}

// NewBudgetManager creates a new budget manager with background expiry checks.
func NewBudgetManager(cfg BudgetManagerConfig) *BudgetManager {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 30 * time.Second
	}

	bm := &BudgetManager{
		store:     cfg.Store,
		cache:     make(map[string]*TokenBudget),
		cacheTime: make(map[string]time.Time),
		alertFn:   cfg.AlertFn,
		logger:    cfg.Logger,
		stopCh:    make(chan struct{}),
		cacheTTL:  cfg.CacheTTL,
	}

	return bm
}

// StartResetLoop runs a background goroutine that resets expired budgets at the given interval.
func (b *BudgetManager) StartResetLoop(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := b.ResetExpired(ctx); err != nil {
					b.logger.Printf("[budget_manager] reset expired error: %v", err)
				}
				cancel()
			case <-b.stopCh:
				return
			}
		}
	}()
}

// Stop terminates the background reset loop.
func (b *BudgetManager) Stop() {
	close(b.stopCh)
}

// CheckBudget verifies whether the estimated token usage fits within applicable budgets.
func (b *BudgetManager) CheckBudget(ctx context.Context, tenantID, userID string, estimatedTokens int) (*BudgetCheckResult, error) {
	if tenantID == "" {
		return nil, errors.New("tenantID is required")
	}
	if estimatedTokens < 0 {
		return nil, errors.New("estimatedTokens must be non-negative")
	}

	// Gather applicable budgets: tenant-level and user-level
	budgets, err := b.getApplicableBudgets(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get budgets: %w", err)
	}

	// No budgets configured means unlimited
	if len(budgets) == 0 {
		return &BudgetCheckResult{
			Allowed:         true,
			RemainingTokens: -1, // unlimited
			RemainingCost:   -1,
		}, nil
	}

	result := &BudgetCheckResult{
		Allowed:         true,
		RemainingTokens: int64(^uint64(0) >> 1), // max int64
		RemainingCost:   1e18,
	}

	for _, budget := range budgets {
		remaining := budget.MaxTokens - budget.Used
		remainingCost := budget.MaxCostUSD - budget.CostUsed

		if remaining < result.RemainingTokens {
			result.RemainingTokens = remaining
		}
		if remainingCost < result.RemainingCost {
			result.RemainingCost = remainingCost
		}

		// Calculate usage percentage (use the higher of token % or cost %)
		usedPct := 0.0
		if budget.MaxTokens > 0 {
			usedPct = float64(budget.Used) / float64(budget.MaxTokens) * 100
		}
		if budget.MaxCostUSD > 0 {
			costPct := budget.CostUsed / budget.MaxCostUSD * 100
			if costPct > usedPct {
				usedPct = costPct
			}
		}
		if usedPct > result.UsedPct {
			result.UsedPct = usedPct
		}

		// Check if estimated tokens would exceed the budget
		wouldExceedTokens := budget.MaxTokens > 0 && (budget.Used+int64(estimatedTokens)) > budget.MaxTokens
		wouldExceedCost := false // cost check happens at recording time since we don't know cost yet

		if wouldExceedTokens || wouldExceedCost {
			if budget.HardCap {
				result.Allowed = false
				result.DenyReason = fmt.Sprintf(
					"token budget exceeded for %s/%s: used %d/%d tokens (%.1f%%)",
					budget.Scope, budget.ScopeID, budget.Used, budget.MaxTokens, usedPct,
				)
				b.logger.Printf("[budget_manager] DENIED tenant=%s user=%s budget=%s reason=%s",
					tenantID, userID, budget.ID, result.DenyReason)
				return result, nil
			}
			// Soft cap: allow but warn
			result.Warning = true
			result.WarningMessage = fmt.Sprintf(
				"token budget will be exceeded for %s/%s: used %d/%d tokens (%.1f%%)",
				budget.Scope, budget.ScopeID, budget.Used, budget.MaxTokens, usedPct,
			)
		}

		// Alert threshold check
		if budget.AlertAt > 0 && usedPct >= budget.AlertAt {
			result.Warning = true
			if result.WarningMessage == "" {
				result.WarningMessage = fmt.Sprintf(
					"budget alert threshold reached for %s/%s: %.1f%% used (alert at %.0f%%)",
					budget.Scope, budget.ScopeID, usedPct, budget.AlertAt,
				)
			}
			b.publishAlert(budget)
		}
	}

	return result, nil
}

// RecordUsage records actual token usage and cost after a successful LLM call.
func (b *BudgetManager) RecordUsage(ctx context.Context, tenantID, userID string, promptTokens, completionTokens int, costUSD float64) error {
	if tenantID == "" {
		return errors.New("tenantID is required")
	}

	totalTokens := int64(promptTokens + completionTokens)

	budgets, err := b.getApplicableBudgets(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("failed to get budgets: %w", err)
	}

	for _, budget := range budgets {
		// Update in store
		newUsed := budget.Used + totalTokens
		newCostUsed := budget.CostUsed + costUSD

		if err := b.store.UpdateBudgetUsage(ctx, budget.ID, newUsed, newCostUsed); err != nil {
			b.logger.Printf("[budget_manager] failed to update usage for budget %s: %v", budget.ID, err)
			return fmt.Errorf("failed to update budget %s: %w", budget.ID, err)
		}

		// Update cache
		b.mu.Lock()
		if cached, ok := b.cache[budget.ID]; ok {
			cached.Used = newUsed
			cached.CostUsed = newCostUsed
		}
		b.mu.Unlock()

		// Check if alert threshold now reached
		usedPct := 0.0
		if budget.MaxTokens > 0 {
			usedPct = float64(newUsed) / float64(budget.MaxTokens) * 100
		}
		if budget.MaxCostUSD > 0 {
			costPct := newCostUsed / budget.MaxCostUSD * 100
			if costPct > usedPct {
				usedPct = costPct
			}
		}

		if budget.AlertAt > 0 && usedPct >= budget.AlertAt {
			updatedBudget := budget
			updatedBudget.Used = newUsed
			updatedBudget.CostUsed = newCostUsed
			b.publishAlert(updatedBudget)
		}

		b.logger.Printf("[budget_manager] recorded usage tenant=%s user=%s budget=%s tokens=%d cost=%.6f used=%d/%d",
			tenantID, userID, budget.ID, totalTokens, costUSD, newUsed, budget.MaxTokens)
	}

	return nil
}

// GetUsage returns a summary of all budgets for a tenant, optionally filtered by period.
func (b *BudgetManager) GetUsage(ctx context.Context, tenantID string, period string) (*UsageSummary, error) {
	if tenantID == "" {
		return nil, errors.New("tenantID is required")
	}

	budgets, err := b.store.GetBudgets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get budgets: %w", err)
	}

	// Filter by period if specified
	if period != "" {
		var filtered []TokenBudget
		for _, bgt := range budgets {
			if bgt.Period == period {
				filtered = append(filtered, bgt)
			}
		}
		budgets = filtered
	}

	return &UsageSummary{Budgets: budgets}, nil
}

// ResetExpired finds all budgets past their reset time and resets their usage counters.
func (b *BudgetManager) ResetExpired(ctx context.Context) error {
	now := time.Now().UTC()

	expired, err := b.store.ListExpiredBudgets(ctx, now)
	if err != nil {
		return fmt.Errorf("failed to list expired budgets: %w", err)
	}

	for _, budget := range expired {
		newResetAt := calculateNextReset(budget.Period, now)

		if err := b.store.ResetBudget(ctx, budget.ID, newResetAt); err != nil {
			b.logger.Printf("[budget_manager] failed to reset budget %s: %v", budget.ID, err)
			continue
		}

		// Invalidate cache entry
		b.mu.Lock()
		delete(b.cache, budget.ID)
		delete(b.cacheTime, budget.ID)
		b.mu.Unlock()

		b.logger.Printf("[budget_manager] reset budget %s (%s/%s) next_reset=%s",
			budget.ID, budget.Scope, budget.ScopeID, newResetAt.Format(time.RFC3339))
	}

	return nil
}

// getApplicableBudgets returns tenant-level and user-level budgets from cache or store.
func (b *BudgetManager) getApplicableBudgets(ctx context.Context, tenantID, userID string) ([]TokenBudget, error) {
	var all []TokenBudget

	// Tenant-level budgets
	tenantBudgets, err := b.getCachedOrFetch(ctx, tenantID, "tenant", tenantID)
	if err != nil {
		return nil, err
	}
	all = append(all, tenantBudgets...)

	// User-level budgets
	if userID != "" {
		userBudgets, err := b.getCachedOrFetch(ctx, tenantID, "user", userID)
		if err != nil {
			return nil, err
		}
		all = append(all, userBudgets...)
	}

	return all, nil
}

// getCachedOrFetch looks up budgets in cache first, falls back to store.
func (b *BudgetManager) getCachedOrFetch(ctx context.Context, tenantID, scope, scopeID string) ([]TokenBudget, error) {
	cacheKey := tenantID + ":" + scope + ":" + scopeID

	b.mu.RLock()
	if t, ok := b.cacheTime[cacheKey]; ok && time.Since(t) < b.cacheTTL {
		// Collect all cached budgets matching this scope
		var results []TokenBudget
		for _, bgt := range b.cache {
			if bgt.TenantID == tenantID && bgt.Scope == scope && bgt.ScopeID == scopeID {
				results = append(results, *bgt)
			}
		}
		b.mu.RUnlock()
		return results, nil
	}
	b.mu.RUnlock()

	// Fetch from store
	budgets, err := b.store.GetBudgetsByScope(ctx, tenantID, scope, scopeID)
	if err != nil {
		return nil, err
	}

	// Update cache
	b.mu.Lock()
	for i := range budgets {
		bgt := budgets[i]
		b.cache[bgt.ID] = &bgt
	}
	b.cacheTime[cacheKey] = time.Now()
	b.mu.Unlock()

	return budgets, nil
}

func (b *BudgetManager) publishAlert(budget TokenBudget) {
	if b.alertFn == nil {
		return
	}

	usedPct := 0.0
	if budget.MaxTokens > 0 {
		usedPct = float64(budget.Used) / float64(budget.MaxTokens) * 100
	}

	alert := BudgetAlert{
		TenantID:   budget.TenantID,
		Scope:      budget.Scope,
		ScopeID:    budget.ScopeID,
		UsedPct:    usedPct,
		UsedTokens: budget.Used,
		MaxTokens:  budget.MaxTokens,
		CostUsed:   budget.CostUsed,
		MaxCost:    budget.MaxCostUSD,
		Period:     budget.Period,
		Timestamp:  time.Now().UTC(),
	}

	// Fire asynchronously to avoid blocking the request path
	go b.alertFn(alert)
}

// calculateNextReset computes the next reset time based on the budget period.
func calculateNextReset(period string, from time.Time) time.Time {
	switch period {
	case "daily":
		next := from.Truncate(24 * time.Hour).Add(24 * time.Hour)
		return next
	case "weekly":
		// Reset on Monday at midnight UTC
		daysUntilMonday := (8 - int(from.Weekday())) % 7
		if daysUntilMonday == 0 {
			daysUntilMonday = 7
		}
		next := from.Truncate(24 * time.Hour).Add(time.Duration(daysUntilMonday) * 24 * time.Hour)
		return next
	case "monthly":
		// First day of next month
		y, m, _ := from.Date()
		next := time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
		return next
	default:
		// Default to monthly
		y, m, _ := from.Date()
		return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
	}
}
