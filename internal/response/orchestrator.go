// Package response implements the semi-automated response orchestrator.
// It manages an approval queue, executes approved actions, and supports rollback.
package response

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// Orchestrator manages the response action lifecycle:
// pending → approved/denied → executed → (optional) rolled_back
type Orchestrator struct {
	cfg     config.ResponseConfig
	exec    Executor
	store   ActionStore
	logger  zerolog.Logger
	mu      sync.RWMutex

	// Callbacks for alerting
	onAction  func(types.ResponseAction) // Called when action is queued
	onExecute func(types.ResponseAction) // Called when action is executed
}

// ActionStore persists response actions (implemented by storage layer).
type ActionStore interface {
	SaveAction(action *types.ResponseAction) error
	GetAction(id string) (*types.ResponseAction, error)
	GetPendingActions() ([]types.ResponseAction, error)
	UpdateAction(action *types.ResponseAction) error
	GetRecentActions(limit int) ([]types.ResponseAction, error)
}

// Executor performs platform-specific defensive actions.
type Executor interface {
	BlockIP(ctx context.Context, ip string) (rollbackCmd string, err error)
	UnblockIP(ctx context.Context, ip string) error
	DisableUser(ctx context.Context, username string) (rollbackCmd string, err error)
	EnableUser(ctx context.Context, username string) error
	KillProcess(ctx context.Context, pid string) error
	IsolateContainer(ctx context.Context, containerID string) (rollbackCmd string, err error)
}

// NewOrchestrator creates a new response orchestrator.
func NewOrchestrator(cfg config.ResponseConfig, exec Executor, store ActionStore, logger zerolog.Logger) *Orchestrator {
	return &Orchestrator{
		cfg:    cfg,
		exec:   exec,
		store:  store,
		logger: logger.With().Str("component", "response").Logger(),
	}
}

// OnAction sets a callback for when a new action is queued.
func (o *Orchestrator) OnAction(fn func(types.ResponseAction)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.onAction = fn
}

// OnExecute sets a callback for when an action is executed.
func (o *Orchestrator) OnExecute(fn func(types.ResponseAction)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.onExecute = fn
}

// QueueAction adds a new response action to the pending queue.
func (o *Orchestrator) QueueAction(action types.ResponseAction) error {
	now := time.Now()
	action.ID = fmt.Sprintf("act_%d", now.UnixNano())
	action.Status = types.ActionPending
	action.CreatedAt = now
	action.ExpiresAt = now.Add(o.cfg.ApprovalExpiry)

	if err := o.store.SaveAction(&action); err != nil {
		return fmt.Errorf("saving action: %w", err)
	}

	o.logger.Info().
		Str("id", action.ID).
		Str("type", string(action.Type)).
		Str("target", action.Target).
		Msg("action queued for approval")

	// Auto-approve if configured (dangerous but allowed).
	if o.cfg.AutoApprove {
		return o.Approve(action.ID, "system:auto")
	}

	o.mu.RLock()
	cb := o.onAction
	o.mu.RUnlock()
	if cb != nil {
		cb(action)
	}

	return nil
}

// Approve marks an action as approved and executes it.
func (o *Orchestrator) Approve(actionID, approvedBy string) error {
	action, err := o.store.GetAction(actionID)
	if err != nil {
		return fmt.Errorf("getting action %s: %w", actionID, err)
	}
	if action == nil {
		return fmt.Errorf("action %s not found", actionID)
	}
	if action.Status != types.ActionPending {
		return fmt.Errorf("action %s is %s, not pending", actionID, action.Status)
	}
	if time.Now().After(action.ExpiresAt) {
		action.Status = types.ActionExpired
		o.store.UpdateAction(action)
		return fmt.Errorf("action %s has expired", actionID)
	}

	action.Status = types.ActionApproved
	action.ApprovedBy = approvedBy

	// Execute the action.
	if err := o.execute(context.Background(), action); err != nil {
		action.Status = types.ActionFailed
		o.store.UpdateAction(action)
		return fmt.Errorf("executing action %s: %w", actionID, err)
	}

	now := time.Now()
	action.ExecutedAt = &now
	action.Status = types.ActionExecuted

	if err := o.store.UpdateAction(action); err != nil {
		return fmt.Errorf("updating action %s: %w", actionID, err)
	}

	o.logger.Info().
		Str("id", action.ID).
		Str("type", string(action.Type)).
		Str("approved_by", approvedBy).
		Msg("action approved and executed")

	o.mu.RLock()
	cb := o.onExecute
	o.mu.RUnlock()
	if cb != nil {
		cb(*action)
	}

	return nil
}

// Deny marks an action as denied.
func (o *Orchestrator) Deny(actionID, deniedBy string) error {
	action, err := o.store.GetAction(actionID)
	if err != nil {
		return fmt.Errorf("getting action %s: %w", actionID, err)
	}
	if action == nil {
		return fmt.Errorf("action %s not found", actionID)
	}
	if action.Status != types.ActionPending {
		return fmt.Errorf("action %s is %s, not pending", actionID, action.Status)
	}

	action.Status = types.ActionDenied
	action.ApprovedBy = deniedBy // Reuse field to record who denied

	if err := o.store.UpdateAction(action); err != nil {
		return fmt.Errorf("updating action %s: %w", actionID, err)
	}

	o.logger.Info().
		Str("id", action.ID).
		Str("denied_by", deniedBy).
		Msg("action denied")

	return nil
}

// Rollback reverses an executed action.
func (o *Orchestrator) Rollback(actionID string) error {
	action, err := o.store.GetAction(actionID)
	if err != nil {
		return fmt.Errorf("getting action %s: %w", actionID, err)
	}
	if action == nil {
		return fmt.Errorf("action %s not found", actionID)
	}
	if action.Status != types.ActionExecuted {
		return fmt.Errorf("action %s is %s, cannot rollback", actionID, action.Status)
	}

	// Check rollback window.
	if action.ExecutedAt != nil && time.Since(*action.ExecutedAt) > o.cfg.RollbackWindow {
		return fmt.Errorf("rollback window expired for action %s", actionID)
	}

	// Execute rollback.
	if err := o.rollback(context.Background(), action); err != nil {
		return fmt.Errorf("rolling back action %s: %w", actionID, err)
	}

	action.Status = types.ActionRolledBack
	if err := o.store.UpdateAction(action); err != nil {
		return fmt.Errorf("updating action %s: %w", actionID, err)
	}

	o.logger.Info().
		Str("id", action.ID).
		Str("type", string(action.Type)).
		Msg("action rolled back")

	return nil
}

// execute performs the actual defensive action.
func (o *Orchestrator) execute(ctx context.Context, action *types.ResponseAction) error {
	if o.cfg.DryRun {
		o.logger.Warn().
			Str("type", string(action.Type)).
			Str("target", action.Target).
			Msg("DRY RUN: would execute action")
		action.RollbackCmd = "dry_run"
		return nil
	}

	var rollback string
	var err error

	switch action.Type {
	case types.ActionBlockIP:
		rollback, err = o.exec.BlockIP(ctx, action.Target)
	case types.ActionDisableUser:
		rollback, err = o.exec.DisableUser(ctx, action.Target)
	case types.ActionKillProcess:
		err = o.exec.KillProcess(ctx, action.Target)
	case types.ActionIsolateContainer:
		rollback, err = o.exec.IsolateContainer(ctx, action.Target)
	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}

	if err != nil {
		return err
	}
	action.RollbackCmd = rollback
	return nil
}

// rollback reverses a defensive action.
func (o *Orchestrator) rollback(ctx context.Context, action *types.ResponseAction) error {
	if o.cfg.DryRun {
		o.logger.Warn().Str("id", action.ID).Msg("DRY RUN: would rollback action")
		return nil
	}

	switch action.Type {
	case types.ActionBlockIP:
		return o.exec.UnblockIP(ctx, action.Target)
	case types.ActionDisableUser:
		return o.exec.EnableUser(ctx, action.Target)
	default:
		return fmt.Errorf("rollback not supported for action type: %s", action.Type)
	}
}

// GetPendingActions returns all pending response actions.
func (o *Orchestrator) GetPendingActions() ([]types.ResponseAction, error) {
	return o.store.GetPendingActions()
}

// ExpireStaleActions marks expired pending actions.
func (o *Orchestrator) ExpireStaleActions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			actions, err := o.store.GetPendingActions()
			if err != nil {
				o.logger.Error().Err(err).Msg("failed to get pending actions for expiry check")
				continue
			}
			now := time.Now()
			for _, action := range actions {
				if now.After(action.ExpiresAt) {
					action.Status = types.ActionExpired
					o.store.UpdateAction(&action)
					o.logger.Info().Str("id", action.ID).Msg("action expired")
				}
			}
		}
	}
}
