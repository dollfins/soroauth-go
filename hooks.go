package soroauth

import (
	"context"
	"time"
)

// HookPhase identifies a stage in the signing lifecycle.
type HookPhase string

const (
	// HookPhasePreimage is called before the preimage is built.
	HookPhasePreimage HookPhase = "preimage"
	// HookPhaseSign is called before a signer signs.
	HookPhaseSign HookPhase = "sign"
	// HookPhasePostSign is called after a signer returns.
	HookPhasePostSign HookPhase = "post_sign"
	// HookPhaseWrite is called before the signature is written
	// onto the entry.
	HookPhaseWrite HookPhase = "write"
)

// HookEvent carries the information for one lifecycle event.
// It is intentionally designed so that no secret material can
// reach a hook:
//
// - Preimage is not included (only its type and variant).
// - The payload hash is not included.
// - Signature material is not included.
// Only structural metadata is passed.
type HookEvent struct {
	// Phase is the lifecycle stage.
	Phase HookPhase
	// CredentialType is the type of credential being signed.
	CredentialType string
	// TargetAddress is the address receiving the signature.
	TargetAddress string
	// ValidUntilLedger is the expiration ledger.
	ValidUntilLedger uint32
	// Duration is the time elapsed for the current phase,
	// set only for timing hooks.
	Duration time.Duration
	// Error is non-nil if the phase ended with an error.
	Error error
	// NodeCount is the number of nodes in the delegate tree
	// (only for delegates-arm entries).
	NodeCount int
	// SignedNodeCount is the number of nodes already signed
	// (only for delegates-arm entries).
	SignedNodeCount int
}

// Hook receives lifecycle events during signing operations.
// Implementations must not modify the event data, and must
// not attempt to extract secret material from it.
//
// Hooks are no-ops by default and zero-cost when unset.
// The library does not log through hooks; callers decide
// what to do with the data.
type Hook interface {
	// Event is called at each lifecycle phase.
	Event(ctx context.Context, e HookEvent) error
}

// NoOpHook is the default hook that does nothing.
// It is zero-cost when unset and satisfies the Hook interface.
type NoOpHook struct{}

// Event is a no-op implementation of Hook.
func (NoOpHook) Event(ctx context.Context, e HookEvent) error { return nil }

// hookList is an optional chain of hooks passed through
// the signing lifecycle.
type hookList struct {
	hooks []Hook
}

// newHookList creates a hookList from the provided hooks.
// Only non-nil hooks are included.
func newHookList(hooks ...Hook) hookList {
	var filtered []Hook
	for _, h := range hooks {
		if h != nil {
			filtered = append(filtered, h)
		}
	}
	return hookList{hooks: filtered}
}

// hasHooks reports whether any hooks are registered.
func (l hookList) hasHooks() bool { return len(l.hooks) > 0 }

// emit calls each hook with the event, preserving ctx.
// Errors from individual hooks are collected but do not
// stop other hooks from firing.
func (l hookList) emit(ctx context.Context, e HookEvent) {
	if !l.hasHooks() {
		return
	}
	for _, h := range l.hooks {
		_ = h.Event(ctx, e) // errors from hooks are not propagated
	}
}
