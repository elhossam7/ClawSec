package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrorCode represents a structured error code for the Sentinel project.
// Codes follow the format E<CATEGORY>-<NUMBER>.
type ErrorCode string

const (
	// Validation errors (EVAL-xxx)
	ErrValidation    ErrorCode = "EVAL-001"
	ErrInvalidInput  ErrorCode = "EVAL-002"
	ErrMissingParam  ErrorCode = "EVAL-003"
	ErrPathTraversal ErrorCode = "EVAL-004"

	// Rate limit errors (ERAT-xxx)
	ErrRateLimit       ErrorCode = "ERAT-001"
	ErrTooManyRequests ErrorCode = "ERAT-002"
	ErrLockout         ErrorCode = "ERAT-003"

	// Platform errors (EPLAT-xxx)
	ErrPlatform         ErrorCode = "EPLAT-001"
	ErrCommandFailed    ErrorCode = "EPLAT-002"
	ErrUnsupportedOS    ErrorCode = "EPLAT-003"
	ErrPermissionDenied ErrorCode = "EPLAT-004"

	// LLM errors (ELLM-xxx)
	ErrLLM            ErrorCode = "ELLM-001"
	ErrLLMTimeout     ErrorCode = "ELLM-002"
	ErrLLMRateLimit   ErrorCode = "ELLM-003"
	ErrLLMInvalidResp ErrorCode = "ELLM-004"
	ErrLLMAllFailed   ErrorCode = "ELLM-005"

	// Storage errors (ESTO-xxx)
	ErrStorage      ErrorCode = "ESTO-001"
	ErrNotFound     ErrorCode = "ESTO-002"
	ErrDuplicate    ErrorCode = "ESTO-003"
	ErrDBConnection ErrorCode = "ESTO-004"

	// Auth errors (EAUTH-xxx)
	ErrAuth           ErrorCode = "EAUTH-001"
	ErrInvalidCreds   ErrorCode = "EAUTH-002"
	ErrSessionExpired ErrorCode = "EAUTH-003"
	ErrCSRFInvalid    ErrorCode = "EAUTH-004"

	// Rule errors (ERULE-xxx)
	ErrRule         ErrorCode = "ERULE-001"
	ErrRuleCompile  ErrorCode = "ERULE-002"
	ErrRuleNotFound ErrorCode = "ERULE-003"
)

// SentinelError is the base error type with structured error codes.
// It carries a machine-readable ErrorCode, a human-readable Message,
// an optional wrapped Cause, and arbitrary key-value Details for context.
type SentinelError struct {
	Code    ErrorCode
	Message string
	Cause   error
	Details map[string]interface{}
}

// Error returns the string representation in "[CODE] message" format.
// If a Cause is present it is appended after a colon separator.
func (e *SentinelError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying Cause so that errors.Is / errors.As
// can walk the error chain.
func (e *SentinelError) Unwrap() error {
	return e.Cause
}

// WithDetails adds a key-value pair of contextual information to the
// error and returns the same pointer for convenient chaining.
func (e *SentinelError) WithDetails(key string, value interface{}) *SentinelError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// ---------------------------------------------------------------------------
// Constructor helpers
// ---------------------------------------------------------------------------

// New creates a new SentinelError with the given code and message.
func New(code ErrorCode, message string) *SentinelError {
	return &SentinelError{
		Code:    code,
		Message: message,
	}
}

// Wrap creates a new SentinelError that wraps an existing error as its Cause.
func Wrap(code ErrorCode, message string, cause error) *SentinelError {
	return &SentinelError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Is reports whether any error in err's chain carries the given ErrorCode.
// It walks the chain using errors.Unwrap so it works with arbitrarily nested
// wrapped errors.
func Is(err error, code ErrorCode) bool {
	for err != nil {
		var se *SentinelError
		if errors.As(err, &se) {
			if se.Code == code {
				return true
			}
		}
		err = errors.Unwrap(err)
	}
	return false
}

// GetCode extracts the ErrorCode from the first SentinelError found in err's
// chain. If none is found it returns an empty ErrorCode.
func GetCode(err error) ErrorCode {
	var se *SentinelError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// ---------------------------------------------------------------------------
// HTTP status mapping
// ---------------------------------------------------------------------------

// ToHTTPStatus maps an ErrorCode to the most appropriate HTTP status code.
// Unknown codes default to 500 Internal Server Error.
func ToHTTPStatus(code ErrorCode) int {
	// First, check the exact code.
	if status, ok := codeToHTTPStatus[code]; ok {
		return status
	}

	// Fall back to the error category prefix so that new codes in a known
	// category still get a reasonable default.
	prefix := string(code)
	if idx := strings.Index(prefix, "-"); idx != -1 {
		prefix = prefix[:idx]
	}
	if status, ok := prefixToHTTPStatus[prefix]; ok {
		return status
	}

	return http.StatusInternalServerError
}

// codeToHTTPStatus maps individual error codes to HTTP status codes.
var codeToHTTPStatus = map[ErrorCode]int{
	// Validation errors -> 400 Bad Request
	ErrValidation:    http.StatusBadRequest,
	ErrInvalidInput:  http.StatusBadRequest,
	ErrMissingParam:  http.StatusBadRequest,
	ErrPathTraversal: http.StatusBadRequest,

	// Rate limit errors -> 429 Too Many Requests
	ErrRateLimit:       http.StatusTooManyRequests,
	ErrTooManyRequests: http.StatusTooManyRequests,
	ErrLockout:         http.StatusTooManyRequests,

	// Platform errors -> 500 Internal Server Error (except permission)
	ErrPlatform:         http.StatusInternalServerError,
	ErrCommandFailed:    http.StatusInternalServerError,
	ErrUnsupportedOS:    http.StatusInternalServerError,
	ErrPermissionDenied: http.StatusForbidden,

	// LLM errors
	ErrLLM:            http.StatusServiceUnavailable,
	ErrLLMTimeout:     http.StatusServiceUnavailable,
	ErrLLMRateLimit:   http.StatusTooManyRequests,
	ErrLLMInvalidResp: http.StatusInternalServerError,
	ErrLLMAllFailed:   http.StatusServiceUnavailable,

	// Storage errors
	ErrStorage:      http.StatusInternalServerError,
	ErrNotFound:     http.StatusNotFound,
	ErrDuplicate:    http.StatusConflict,
	ErrDBConnection: http.StatusServiceUnavailable,

	// Auth errors
	ErrAuth:           http.StatusUnauthorized,
	ErrInvalidCreds:   http.StatusUnauthorized,
	ErrSessionExpired: http.StatusUnauthorized,
	ErrCSRFInvalid:    http.StatusForbidden,

	// Rule errors
	ErrRule:         http.StatusInternalServerError,
	ErrRuleCompile:  http.StatusBadRequest,
	ErrRuleNotFound: http.StatusNotFound,
}

// prefixToHTTPStatus provides category-level fallback mappings.
var prefixToHTTPStatus = map[string]int{
	"EVAL":  http.StatusBadRequest,
	"ERAT":  http.StatusTooManyRequests,
	"EPLAT": http.StatusInternalServerError,
	"ELLM":  http.StatusServiceUnavailable,
	"ESTO":  http.StatusInternalServerError,
	"EAUTH": http.StatusUnauthorized,
	"ERULE": http.StatusInternalServerError,
}
