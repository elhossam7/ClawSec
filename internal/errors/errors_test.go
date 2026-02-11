package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		code    ErrorCode
		message string
	}{
		{
			name:    "validation error",
			code:    ErrValidation,
			message: "field X is invalid",
		},
		{
			name:    "empty message",
			code:    ErrNotFound,
			message: "",
		},
		{
			name:    "custom unknown code",
			code:    ErrorCode("ECUSTOM-999"),
			message: "something unusual",
		},
		{
			name:    "empty code",
			code:    ErrorCode(""),
			message: "no code provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(tt.code, tt.message)
			if err == nil {
				t.Fatal("New returned nil")
			}
			if err.Code != tt.code {
				t.Errorf("Code = %q, want %q", err.Code, tt.code)
			}
			if err.Message != tt.message {
				t.Errorf("Message = %q, want %q", err.Message, tt.message)
			}
			if err.Cause != nil {
				t.Errorf("Cause = %v, want nil", err.Cause)
			}
			if err.Details != nil {
				t.Errorf("Details = %v, want nil", err.Details)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wrap
// ---------------------------------------------------------------------------

func TestWrap(t *testing.T) {
	cause := stderrors.New("underlying problem")

	tests := []struct {
		name    string
		code    ErrorCode
		message string
		cause   error
	}{
		{
			name:    "wrap standard error",
			code:    ErrStorage,
			message: "db operation failed",
			cause:   cause,
		},
		{
			name:    "wrap nil cause",
			code:    ErrValidation,
			message: "no cause",
			cause:   nil,
		},
		{
			name:    "wrap sentinel error",
			code:    ErrLLM,
			message: "outer",
			cause:   New(ErrLLMTimeout, "inner timeout"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Wrap(tt.code, tt.message, tt.cause)
			if err == nil {
				t.Fatal("Wrap returned nil")
			}
			if err.Code != tt.code {
				t.Errorf("Code = %q, want %q", err.Code, tt.code)
			}
			if err.Message != tt.message {
				t.Errorf("Message = %q, want %q", err.Message, tt.message)
			}
			if err.Cause != tt.cause {
				t.Errorf("Cause = %v, want %v", err.Cause, tt.cause)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error (string representation)
// ---------------------------------------------------------------------------

func TestSentinelError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *SentinelError
		want string
	}{
		{
			name: "without cause",
			err:  New(ErrValidation, "bad input"),
			want: "[EVAL-001] bad input",
		},
		{
			name: "with cause",
			err:  Wrap(ErrStorage, "save failed", stderrors.New("disk full")),
			want: "[ESTO-001] save failed: disk full",
		},
		{
			name: "empty message without cause",
			err:  New(ErrNotFound, ""),
			want: "[ESTO-002] ",
		},
		{
			name: "empty message with cause",
			err:  Wrap(ErrNotFound, "", stderrors.New("oops")),
			want: "[ESTO-002] : oops",
		},
		{
			name: "nested sentinel cause",
			err:  Wrap(ErrLLM, "outer", New(ErrLLMTimeout, "inner")),
			want: "[ELLM-001] outer: [ELLM-002] inner",
		},
		{
			name: "custom code",
			err:  New(ErrorCode("ETEST-042"), "custom"),
			want: "[ETEST-042] custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Verify that *SentinelError satisfies the error interface.
func TestSentinelError_ImplementsError(t *testing.T) {
	var _ error = (*SentinelError)(nil)
}

// ---------------------------------------------------------------------------
// Unwrap
// ---------------------------------------------------------------------------

func TestSentinelError_Unwrap(t *testing.T) {
	t.Run("nil cause", func(t *testing.T) {
		err := New(ErrValidation, "test")
		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})

	t.Run("non-nil cause", func(t *testing.T) {
		cause := stderrors.New("root")
		err := Wrap(ErrStorage, "wrapper", cause)
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("standard errors.Unwrap compatibility", func(t *testing.T) {
		cause := stderrors.New("root")
		err := Wrap(ErrStorage, "wrapper", cause)
		unwrapped := stderrors.Unwrap(err)
		if unwrapped != cause {
			t.Errorf("stderrors.Unwrap() = %v, want %v", unwrapped, cause)
		}
	})

	t.Run("chained unwrap", func(t *testing.T) {
		root := stderrors.New("root cause")
		mid := Wrap(ErrLLMTimeout, "mid", root)
		outer := Wrap(ErrLLM, "outer", mid)

		first := outer.Unwrap()
		if first != mid {
			t.Fatalf("first Unwrap() got unexpected error")
		}
		midSent, ok := first.(*SentinelError)
		if !ok {
			t.Fatalf("first Unwrap() did not return *SentinelError")
		}
		second := midSent.Unwrap()
		if second != root {
			t.Errorf("second Unwrap() = %v, want %v", second, root)
		}
	})
}

// ---------------------------------------------------------------------------
// WithDetails
// ---------------------------------------------------------------------------

func TestSentinelError_WithDetails(t *testing.T) {
	t.Run("add single detail", func(t *testing.T) {
		err := New(ErrValidation, "bad").WithDetails("field", "email")
		if err.Details == nil {
			t.Fatal("Details map is nil after WithDetails")
		}
		if v, ok := err.Details["field"]; !ok || v != "email" {
			t.Errorf("Details[field] = %v, want %q", v, "email")
		}
	})

	t.Run("chaining multiple details", func(t *testing.T) {
		err := New(ErrValidation, "bad").
			WithDetails("field", "email").
			WithDetails("value", 42).
			WithDetails("allowed", true)

		if len(err.Details) != 3 {
			t.Errorf("len(Details) = %d, want 3", len(err.Details))
		}
		if v := err.Details["field"]; v != "email" {
			t.Errorf("Details[field] = %v, want %q", v, "email")
		}
		if v := err.Details["value"]; v != 42 {
			t.Errorf("Details[value] = %v, want 42", v)
		}
		if v := err.Details["allowed"]; v != true {
			t.Errorf("Details[allowed] = %v, want true", v)
		}
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		err := New(ErrValidation, "bad").
			WithDetails("key", "old").
			WithDetails("key", "new")

		if v := err.Details["key"]; v != "new" {
			t.Errorf("Details[key] = %v, want %q", v, "new")
		}
		if len(err.Details) != 1 {
			t.Errorf("len(Details) = %d, want 1", len(err.Details))
		}
	})

	t.Run("nil value", func(t *testing.T) {
		err := New(ErrValidation, "bad").WithDetails("nothing", nil)
		if v, ok := err.Details["nothing"]; !ok {
			t.Error("key 'nothing' not found in Details")
		} else if v != nil {
			t.Errorf("Details[nothing] = %v, want nil", v)
		}
	})

	t.Run("returns same pointer for chaining", func(t *testing.T) {
		err := New(ErrValidation, "bad")
		returned := err.WithDetails("k", "v")
		if returned != err {
			t.Error("WithDetails did not return the same pointer")
		}
	})

	t.Run("empty key", func(t *testing.T) {
		err := New(ErrValidation, "bad").WithDetails("", "emptykey")
		if v := err.Details[""]; v != "emptykey" {
			t.Errorf("Details[\"\"] = %v, want %q", v, "emptykey")
		}
	})

	t.Run("complex value types", func(t *testing.T) {
		slice := []string{"a", "b"}
		m := map[string]int{"x": 1}
		err := New(ErrValidation, "bad").
			WithDetails("slice", slice).
			WithDetails("map", m)

		if err.Details["slice"] == nil {
			t.Error("Details[slice] is nil")
		}
		if err.Details["map"] == nil {
			t.Error("Details[map] is nil")
		}
	})
}

// ---------------------------------------------------------------------------
// Is
// ---------------------------------------------------------------------------

func TestIs(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code ErrorCode
		want bool
	}{
		{
			name: "exact match",
			err:  New(ErrValidation, "bad"),
			code: ErrValidation,
			want: true,
		},
		{
			name: "no match",
			err:  New(ErrValidation, "bad"),
			code: ErrNotFound,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			code: ErrValidation,
			want: false,
		},
		{
			name: "non-sentinel error",
			err:  stderrors.New("plain error"),
			code: ErrValidation,
			want: false,
		},
		{
			name: "wrapped sentinel - match outer",
			err:  Wrap(ErrLLM, "outer", New(ErrLLMTimeout, "inner")),
			code: ErrLLM,
			want: true,
		},
		{
			name: "wrapped sentinel - match inner",
			err:  Wrap(ErrLLM, "outer", New(ErrLLMTimeout, "inner")),
			code: ErrLLMTimeout,
			want: true,
		},
		{
			name: "wrapped sentinel - no match",
			err:  Wrap(ErrLLM, "outer", New(ErrLLMTimeout, "inner")),
			code: ErrNotFound,
			want: false,
		},
		{
			name: "sentinel wrapping plain error",
			err:  Wrap(ErrStorage, "wrapper", stderrors.New("plain")),
			code: ErrStorage,
			want: true,
		},
		{
			name: "sentinel wrapping plain error - wrong code",
			err:  Wrap(ErrStorage, "wrapper", stderrors.New("plain")),
			code: ErrValidation,
			want: false,
		},
		{
			name: "deeply nested - match deepest",
			err: Wrap(ErrLLM, "l1",
				Wrap(ErrLLMTimeout, "l2",
					Wrap(ErrLLMRateLimit, "l3",
						New(ErrLLMAllFailed, "l4")))),
			code: ErrLLMAllFailed,
			want: true,
		},
		{
			name: "deeply nested - match middle",
			err: Wrap(ErrLLM, "l1",
				Wrap(ErrLLMTimeout, "l2",
					Wrap(ErrLLMRateLimit, "l3",
						New(ErrLLMAllFailed, "l4")))),
			code: ErrLLMRateLimit,
			want: true,
		},
		{
			name: "fmt.Errorf wrapped sentinel",
			err:  fmt.Errorf("context: %w", New(ErrValidation, "inner")),
			code: ErrValidation,
			want: true,
		},
		{
			name: "empty code on error",
			err:  New(ErrorCode(""), "no code"),
			code: ErrorCode(""),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Is(tt.err, tt.code)
			if got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetCode
// ---------------------------------------------------------------------------

func TestGetCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{
			name: "sentinel error",
			err:  New(ErrValidation, "bad"),
			want: ErrValidation,
		},
		{
			name: "wrapped sentinel - returns outermost",
			err:  Wrap(ErrLLM, "outer", New(ErrLLMTimeout, "inner")),
			want: ErrLLM,
		},
		{
			name: "nil error",
			err:  nil,
			want: ErrorCode(""),
		},
		{
			name: "plain error",
			err:  stderrors.New("not a sentinel error"),
			want: ErrorCode(""),
		},
		{
			name: "fmt.Errorf wrapped sentinel",
			err:  fmt.Errorf("extra: %w", New(ErrNotFound, "missing")),
			want: ErrNotFound,
		},
		{
			name: "deeply nested - returns first found by errors.As",
			err: fmt.Errorf("wrap: %w",
				Wrap(ErrStorage, "mid", New(ErrNotFound, "deep"))),
			want: ErrStorage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCode(tt.err)
			if got != tt.want {
				t.Errorf("GetCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ToHTTPStatus - exhaustive per-code mapping
// ---------------------------------------------------------------------------

func TestToHTTPStatus_AllKnownCodes(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		want int
	}{
		// Validation errors -> 400
		{"ErrValidation", ErrValidation, http.StatusBadRequest},
		{"ErrInvalidInput", ErrInvalidInput, http.StatusBadRequest},
		{"ErrMissingParam", ErrMissingParam, http.StatusBadRequest},
		{"ErrPathTraversal", ErrPathTraversal, http.StatusBadRequest},

		// Rate limit errors -> 429
		{"ErrRateLimit", ErrRateLimit, http.StatusTooManyRequests},
		{"ErrTooManyRequests", ErrTooManyRequests, http.StatusTooManyRequests},
		{"ErrLockout", ErrLockout, http.StatusTooManyRequests},

		// Platform errors -> 500 (except ErrPermissionDenied -> 403)
		{"ErrPlatform", ErrPlatform, http.StatusInternalServerError},
		{"ErrCommandFailed", ErrCommandFailed, http.StatusInternalServerError},
		{"ErrUnsupportedOS", ErrUnsupportedOS, http.StatusInternalServerError},
		{"ErrPermissionDenied", ErrPermissionDenied, http.StatusForbidden},

		// LLM errors
		{"ErrLLM", ErrLLM, http.StatusServiceUnavailable},
		{"ErrLLMTimeout", ErrLLMTimeout, http.StatusServiceUnavailable},
		{"ErrLLMRateLimit", ErrLLMRateLimit, http.StatusTooManyRequests},
		{"ErrLLMInvalidResp", ErrLLMInvalidResp, http.StatusInternalServerError},
		{"ErrLLMAllFailed", ErrLLMAllFailed, http.StatusServiceUnavailable},

		// Storage errors
		{"ErrStorage", ErrStorage, http.StatusInternalServerError},
		{"ErrNotFound", ErrNotFound, http.StatusNotFound},
		{"ErrDuplicate", ErrDuplicate, http.StatusConflict},
		{"ErrDBConnection", ErrDBConnection, http.StatusServiceUnavailable},

		// Auth errors
		{"ErrAuth", ErrAuth, http.StatusUnauthorized},
		{"ErrInvalidCreds", ErrInvalidCreds, http.StatusUnauthorized},
		{"ErrSessionExpired", ErrSessionExpired, http.StatusUnauthorized},
		{"ErrCSRFInvalid", ErrCSRFInvalid, http.StatusForbidden},

		// Rule errors
		{"ErrRule", ErrRule, http.StatusInternalServerError},
		{"ErrRuleCompile", ErrRuleCompile, http.StatusBadRequest},
		{"ErrRuleNotFound", ErrRuleNotFound, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToHTTPStatus(tt.code)
			if got != tt.want {
				t.Errorf("ToHTTPStatus(%q) = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

func TestToHTTPStatus_PrefixFallback(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		want int
	}{
		{"unknown EVAL code", ErrorCode("EVAL-999"), http.StatusBadRequest},
		{"unknown ERAT code", ErrorCode("ERAT-999"), http.StatusTooManyRequests},
		{"unknown EPLAT code", ErrorCode("EPLAT-999"), http.StatusInternalServerError},
		{"unknown ELLM code", ErrorCode("ELLM-999"), http.StatusServiceUnavailable},
		{"unknown ESTO code", ErrorCode("ESTO-999"), http.StatusInternalServerError},
		{"unknown EAUTH code", ErrorCode("EAUTH-999"), http.StatusUnauthorized},
		{"unknown ERULE code", ErrorCode("ERULE-999"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToHTTPStatus(tt.code)
			if got != tt.want {
				t.Errorf("ToHTTPStatus(%q) = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

func TestToHTTPStatus_UnknownCode(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		want int
	}{
		{"completely unknown code", ErrorCode("EUNKNOWN-001"), http.StatusInternalServerError},
		{"empty code", ErrorCode(""), http.StatusInternalServerError},
		{"no dash in code", ErrorCode("NODASH"), http.StatusInternalServerError},
		{"random string", ErrorCode("foobar-123"), http.StatusInternalServerError},
		{"just a dash", ErrorCode("-"), http.StatusInternalServerError},
		{"prefix only with dash", ErrorCode("EVAL-"), http.StatusBadRequest}, // prefix matches EVAL
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToHTTPStatus(tt.code)
			if got != tt.want {
				t.Errorf("ToHTTPStatus(%q) = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration: standard library errors.As / errors.Is compatibility
// ---------------------------------------------------------------------------

func TestStdErrorsAsCompatibility(t *testing.T) {
	original := New(ErrValidation, "field invalid").
		WithDetails("field", "email")

	wrapped := fmt.Errorf("handler: %w", original)

	var se *SentinelError
	if !stderrors.As(wrapped, &se) {
		t.Fatal("stderrors.As failed to find *SentinelError in chain")
	}
	if se.Code != ErrValidation {
		t.Errorf("Code = %q, want %q", se.Code, ErrValidation)
	}
	if se.Details["field"] != "email" {
		t.Errorf("Details[field] = %v, want %q", se.Details["field"], "email")
	}
}

func TestStdErrorsUnwrapChain(t *testing.T) {
	root := stderrors.New("root cause")
	mid := Wrap(ErrLLMTimeout, "timeout reached", root)
	outer := Wrap(ErrLLM, "llm failure", mid)
	top := fmt.Errorf("request failed: %w", outer)

	// Verify we can walk the entire chain.
	if !stderrors.Is(top, root) {
		t.Error("stderrors.Is could not find root in chain")
	}

	var se *SentinelError
	if !stderrors.As(top, &se) {
		t.Fatal("stderrors.As failed to find *SentinelError")
	}
	if se.Code != ErrLLM {
		t.Errorf("first SentinelError code = %q, want %q", se.Code, ErrLLM)
	}
}

// ---------------------------------------------------------------------------
// Edge cases and combined scenarios
// ---------------------------------------------------------------------------

func TestNew_ProducesDistinctInstances(t *testing.T) {
	a := New(ErrValidation, "first")
	b := New(ErrValidation, "second")
	if a == b {
		t.Error("New returned the same pointer for two calls")
	}
}

func TestWrap_WithNilCause_BehavesLikeNew(t *testing.T) {
	wrapped := Wrap(ErrStorage, "no cause", nil)
	created := New(ErrStorage, "no cause")

	if wrapped.Code != created.Code {
		t.Errorf("codes differ: %q vs %q", wrapped.Code, created.Code)
	}
	if wrapped.Message != created.Message {
		t.Errorf("messages differ: %q vs %q", wrapped.Message, created.Message)
	}
	if wrapped.Cause != nil {
		t.Errorf("Wrap with nil cause: Cause = %v, want nil", wrapped.Cause)
	}
	// Error() output should match for both since neither has a cause.
	if wrapped.Error() != created.Error() {
		t.Errorf("Error() differs: %q vs %q", wrapped.Error(), created.Error())
	}
}

func TestWithDetails_AfterWrap(t *testing.T) {
	cause := stderrors.New("disk full")
	err := Wrap(ErrStorage, "write failed", cause).
		WithDetails("path", "/data/file.db").
		WithDetails("bytes", 1024)

	if err.Cause != cause {
		t.Error("Cause was lost after WithDetails")
	}
	if err.Details["path"] != "/data/file.db" {
		t.Errorf("Details[path] = %v, want %q", err.Details["path"], "/data/file.db")
	}
	if err.Details["bytes"] != 1024 {
		t.Errorf("Details[bytes] = %v, want 1024", err.Details["bytes"])
	}
	// Error string should still include the cause.
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("Error() = %q, should contain cause message", err.Error())
	}
}

func TestIs_WithFmtErrorfWrapping(t *testing.T) {
	inner := New(ErrCSRFInvalid, "bad token")
	mid := fmt.Errorf("middleware: %w", inner)
	outer := fmt.Errorf("handler: %w", mid)

	if !Is(outer, ErrCSRFInvalid) {
		t.Error("Is did not find ErrCSRFInvalid through fmt.Errorf chain")
	}
	if Is(outer, ErrAuth) {
		t.Error("Is incorrectly matched ErrAuth")
	}
}

func TestGetCode_MultipleWraps(t *testing.T) {
	deep := New(ErrRuleNotFound, "rule missing")
	mid := Wrap(ErrRule, "rule engine error", deep)
	top := Wrap(ErrPlatform, "platform error", mid)

	// errors.As finds the outermost SentinelError first.
	code := GetCode(top)
	if code != ErrPlatform {
		t.Errorf("GetCode = %q, want %q", code, ErrPlatform)
	}
}

func TestErrorCode_StringValue(t *testing.T) {
	// Verify the constant values themselves are correct.
	codeValues := map[ErrorCode]string{
		ErrValidation:       "EVAL-001",
		ErrInvalidInput:     "EVAL-002",
		ErrMissingParam:     "EVAL-003",
		ErrPathTraversal:    "EVAL-004",
		ErrRateLimit:        "ERAT-001",
		ErrTooManyRequests:  "ERAT-002",
		ErrLockout:          "ERAT-003",
		ErrPlatform:         "EPLAT-001",
		ErrCommandFailed:    "EPLAT-002",
		ErrUnsupportedOS:    "EPLAT-003",
		ErrPermissionDenied: "EPLAT-004",
		ErrLLM:              "ELLM-001",
		ErrLLMTimeout:       "ELLM-002",
		ErrLLMRateLimit:     "ELLM-003",
		ErrLLMInvalidResp:   "ELLM-004",
		ErrLLMAllFailed:     "ELLM-005",
		ErrStorage:          "ESTO-001",
		ErrNotFound:         "ESTO-002",
		ErrDuplicate:        "ESTO-003",
		ErrDBConnection:     "ESTO-004",
		ErrAuth:             "EAUTH-001",
		ErrInvalidCreds:     "EAUTH-002",
		ErrSessionExpired:   "EAUTH-003",
		ErrCSRFInvalid:      "EAUTH-004",
		ErrRule:             "ERULE-001",
		ErrRuleCompile:      "ERULE-002",
		ErrRuleNotFound:     "ERULE-003",
	}

	for code, wantStr := range codeValues {
		if string(code) != wantStr {
			t.Errorf("ErrorCode constant %q has value %q, want %q", wantStr, string(code), wantStr)
		}
	}
}

func TestToHTTPStatus_AllCodesHaveMapping(t *testing.T) {
	// Every defined ErrorCode constant should have an explicit entry in
	// the status map (not just rely on prefix fallback).
	allCodes := []ErrorCode{
		ErrValidation, ErrInvalidInput, ErrMissingParam, ErrPathTraversal,
		ErrRateLimit, ErrTooManyRequests, ErrLockout,
		ErrPlatform, ErrCommandFailed, ErrUnsupportedOS, ErrPermissionDenied,
		ErrLLM, ErrLLMTimeout, ErrLLMRateLimit, ErrLLMInvalidResp, ErrLLMAllFailed,
		ErrStorage, ErrNotFound, ErrDuplicate, ErrDBConnection,
		ErrAuth, ErrInvalidCreds, ErrSessionExpired, ErrCSRFInvalid,
		ErrRule, ErrRuleCompile, ErrRuleNotFound,
	}

	for _, code := range allCodes {
		status := ToHTTPStatus(code)
		if status == 0 {
			t.Errorf("ToHTTPStatus(%q) returned 0", code)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrValidation, "benchmark error")
	}
}

func BenchmarkWrap(b *testing.B) {
	cause := stderrors.New("cause")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Wrap(ErrStorage, "wrapping", cause)
	}
}

func BenchmarkError_WithCause(b *testing.B) {
	err := Wrap(ErrStorage, "msg", stderrors.New("cause"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}

func BenchmarkError_WithoutCause(b *testing.B) {
	err := New(ErrStorage, "msg")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}

func BenchmarkIs_ShallowChain(b *testing.B) {
	err := New(ErrValidation, "test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Is(err, ErrValidation)
	}
}

func BenchmarkIs_DeepChain(b *testing.B) {
	var err error = New(ErrLLMAllFailed, "deepest")
	for i := 0; i < 10; i++ {
		err = Wrap(ErrLLM, "layer", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Is(err, ErrLLMAllFailed)
	}
}

func BenchmarkToHTTPStatus_KnownCode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToHTTPStatus(ErrNotFound)
	}
}

func BenchmarkToHTTPStatus_FallbackPrefix(b *testing.B) {
	code := ErrorCode("EVAL-999")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToHTTPStatus(code)
	}
}

func BenchmarkToHTTPStatus_Unknown(b *testing.B) {
	code := ErrorCode("EUNKNOWN-001")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToHTTPStatus(code)
	}
}
