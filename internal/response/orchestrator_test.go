package response

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// ---------------------------------------------------------------------------
// Mock store and executor
// ---------------------------------------------------------------------------

type mockActionStore struct {
	actions map[string]*types.ResponseAction
}

func newMockActionStore() *mockActionStore {
	return &mockActionStore{actions: make(map[string]*types.ResponseAction)}
}

func (m *mockActionStore) SaveAction(a *types.ResponseAction) error {
	m.actions[a.ID] = a
	return nil
}

func (m *mockActionStore) GetAction(id string) (*types.ResponseAction, error) {
	a, ok := m.actions[id]
	if !ok {
		return nil, nil
	}
	return a, nil
}

func (m *mockActionStore) GetPendingActions() ([]types.ResponseAction, error) {
	var result []types.ResponseAction
	for _, a := range m.actions {
		if a.Status == types.ActionPending {
			result = append(result, *a)
		}
	}
	return result, nil
}

func (m *mockActionStore) UpdateAction(a *types.ResponseAction) error {
	m.actions[a.ID] = a
	return nil
}

func (m *mockActionStore) GetRecentActions(limit int) ([]types.ResponseAction, error) {
	var result []types.ResponseAction
	for _, a := range m.actions {
		result = append(result, *a)
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

type mockExecutor struct {
	blockCalled    bool
	unblockCalled  bool
	disableCalled  bool
	enableCalled   bool
	killCalled     bool
	isolateCalled  bool
	failOnExecute  bool
}

func (m *mockExecutor) BlockIP(ctx context.Context, ip string) (string, error) {
	m.blockCalled = true
	if m.failOnExecute {
		return "", fmt.Errorf("mock block failed")
	}
	return "unblock " + ip, nil
}

func (m *mockExecutor) UnblockIP(ctx context.Context, ip string) error {
	m.unblockCalled = true
	return nil
}

func (m *mockExecutor) DisableUser(ctx context.Context, username string) (string, error) {
	m.disableCalled = true
	if m.failOnExecute {
		return "", fmt.Errorf("mock disable failed")
	}
	return "enable " + username, nil
}

func (m *mockExecutor) EnableUser(ctx context.Context, username string) error {
	m.enableCalled = true
	return nil
}

func (m *mockExecutor) KillProcess(ctx context.Context, pid string) error {
	m.killCalled = true
	return nil
}

func (m *mockExecutor) IsolateContainer(ctx context.Context, id string) (string, error) {
	m.isolateCalled = true
	return "unisolate " + id, nil
}

func newTestOrchestrator() (*Orchestrator, *mockActionStore, *mockExecutor) {
	store := newMockActionStore()
	exec := &mockExecutor{}
	cfg := config.ResponseConfig{
		ApprovalExpiry: 15 * time.Minute,
		RollbackWindow: 1 * time.Hour,
	}
	logger := zerolog.Nop()
	orch := NewOrchestrator(cfg, exec, store, logger)
	return orch, store, exec
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestQueueAction_Pending(t *testing.T) {
	orch, store, _ := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "brute force",
		Severity: types.SeverityHigh,
	}

	if err := orch.QueueAction(action); err != nil {
		t.Fatalf("QueueAction: %v", err)
	}

	// Should have one pending action.
	pending, _ := store.GetPendingActions()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending action, got %d", len(pending))
	}
	if pending[0].Status != types.ActionPending {
		t.Errorf("expected pending status, got %s", pending[0].Status)
	}
}

func TestQueueAction_AutoApprove(t *testing.T) {
	store := newMockActionStore()
	exec := &mockExecutor{}
	cfg := config.ResponseConfig{
		AutoApprove:    true,
		ApprovalExpiry: 15 * time.Minute,
		RollbackWindow: 1 * time.Hour,
	}
	orch := NewOrchestrator(cfg, exec, store, zerolog.Nop())

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "auto test",
		Severity: types.SeverityHigh,
	}

	if err := orch.QueueAction(action); err != nil {
		t.Fatalf("QueueAction (auto-approve): %v", err)
	}

	if !exec.blockCalled {
		t.Error("expected BlockIP to be called with auto-approve")
	}
}

func TestApprove_ExecutesAction(t *testing.T) {
	orch, store, exec := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	// Get the action ID.
	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	if err := orch.Approve(id, "admin"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if !exec.blockCalled {
		t.Error("expected BlockIP to be called")
	}

	a, _ := store.GetAction(id)
	if a.Status != types.ActionExecuted {
		t.Errorf("expected executed status, got %s", a.Status)
	}
	if a.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy = %q, want admin", a.ApprovedBy)
	}
}

func TestApprove_ActionNotFound(t *testing.T) {
	orch, _, _ := newTestOrchestrator()
	err := orch.Approve("nonexistent_id", "admin")
	if err == nil {
		t.Error("expected error for nonexistent action")
	}
}

func TestApprove_AlreadyApproved(t *testing.T) {
	orch, store, _ := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	orch.Approve(id, "admin")

	// Second approve should fail.
	err := orch.Approve(id, "admin")
	if err == nil {
		t.Error("expected error for already approved action")
	}
}

func TestDeny_Action(t *testing.T) {
	orch, store, _ := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	if err := orch.Deny(id, "admin"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	a, _ := store.GetAction(id)
	if a.Status != types.ActionDenied {
		t.Errorf("expected denied status, got %s", a.Status)
	}
}

func TestRollback_ExecutedAction(t *testing.T) {
	orch, store, exec := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	orch.Approve(id, "admin")

	if err := orch.Rollback(id); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if !exec.unblockCalled {
		t.Error("expected UnblockIP to be called on rollback")
	}

	a, _ := store.GetAction(id)
	if a.Status != types.ActionRolledBack {
		t.Errorf("expected rolled_back status, got %s", a.Status)
	}
}

func TestRollback_NotExecuted(t *testing.T) {
	orch, store, _ := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	// Try rollback without approval — should fail.
	err := orch.Rollback(id)
	if err == nil {
		t.Error("expected error for non-executed action rollback")
	}
}

func TestDryRun_NoExecution(t *testing.T) {
	store := newMockActionStore()
	exec := &mockExecutor{}
	cfg := config.ResponseConfig{
		AutoApprove:    true,
		DryRun:         true,
		ApprovalExpiry: 15 * time.Minute,
		RollbackWindow: 1 * time.Hour,
	}
	orch := NewOrchestrator(cfg, exec, store, zerolog.Nop())

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "dry run test",
		Severity: types.SeverityHigh,
	}

	if err := orch.QueueAction(action); err != nil {
		t.Fatalf("QueueAction: %v", err)
	}

	if exec.blockCalled {
		t.Error("BlockIP should NOT be called in dry run mode")
	}
}

func TestOnAction_Callback(t *testing.T) {
	orch, _, _ := newTestOrchestrator()

	var called bool
	orch.OnAction(func(a types.ResponseAction) {
		called = true
	})

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "callback test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	if !called {
		t.Error("expected OnAction callback to be called")
	}
}

func TestOnExecute_Callback(t *testing.T) {
	orch, store, _ := newTestOrchestrator()

	var called bool
	orch.OnExecute(func(a types.ResponseAction) {
		called = true
	})

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	orch.Approve(pending[0].ID, "admin")

	if !called {
		t.Error("expected OnExecute callback to be called")
	}
}

func TestSubmitProposal_PolicyCheck(t *testing.T) {
	orch, _, _ := newTestOrchestrator()
	orch.Policy().SetRateLimit("block_ip", 1, time.Hour)

	proposal1 := types.ActionProposal{
		Action: types.ResponseAction{
			Type:     types.ActionBlockIP,
			Target:   "203.0.113.5",
			Severity: types.SeverityHigh,
		},
		Confidence: 0.85,
		RiskScore:  7,
		Reasoning:  "suspicious SSH activity",
	}

	if err := orch.SubmitProposal(proposal1); err != nil {
		t.Fatalf("first proposal: %v", err)
	}

	// Second proposal should be rate limited.
	proposal2 := proposal1
	proposal2.Action.Target = "203.0.113.6"
	if err := orch.SubmitProposal(proposal2); err == nil {
		t.Error("expected rate limit error for second proposal")
	}
}

func TestExecute_DisableUser(t *testing.T) {
	orch, store, exec := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionDisableUser,
		Target:   "jdoe",
		Reason:   "compromised",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	orch.Approve(pending[0].ID, "admin")

	if !exec.disableCalled {
		t.Error("expected DisableUser to be called")
	}
}

func TestExecute_KillProcess(t *testing.T) {
	orch, store, exec := newTestOrchestrator()

	action := types.ResponseAction{
		Type:     types.ActionKillProcess,
		Target:   "12345",
		Reason:   "malicious",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	orch.Approve(pending[0].ID, "admin")

	if !exec.killCalled {
		t.Error("expected KillProcess to be called")
	}
}

func TestApprove_ExecutionFailure(t *testing.T) {
	store := newMockActionStore()
	exec := &mockExecutor{failOnExecute: true}
	cfg := config.ResponseConfig{
		ApprovalExpiry: 15 * time.Minute,
		RollbackWindow: 1 * time.Hour,
	}
	orch := NewOrchestrator(cfg, exec, store, zerolog.Nop())

	action := types.ResponseAction{
		Type:     types.ActionBlockIP,
		Target:   "203.0.113.5",
		Reason:   "test",
		Severity: types.SeverityHigh,
	}
	orch.QueueAction(action)

	pending, _ := store.GetPendingActions()
	id := pending[0].ID

	err := orch.Approve(id, "admin")
	if err == nil {
		t.Error("expected error when execution fails")
	}

	a, _ := store.GetAction(id)
	if a.Status != types.ActionFailed {
		t.Errorf("expected failed status, got %s", a.Status)
	}
}
