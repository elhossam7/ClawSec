package agent

import (
	"fmt"
	"regexp"
	"strings"
)

// InputValidator defends against prompt injection and command injection.
type InputValidator struct {
	maxInputLen    int
	bannedPatterns []*regexp.Regexp
	dangerousShell []string
}

// NewInputValidator creates a validator with sensible defaults.
func NewInputValidator() *InputValidator {
	patterns := []string{
		`(?i)ignore\s+(all\s+)?previous\s+instructions`,
		`(?i)you\s+are\s+now\s+DAN`,
		`(?i)print\s+your\s+system\s+prompt`,
		`(?i)show\s+me\s+your\s+rules`,
		`(?i)disregard\s+(all\s+)?prior`,
		`(?i)override\s+(safety|your\s+training)`,
		`(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions`,
		`(?i)repeat\s+the\s+text\s+above`,
		`(?i)what\s+is\s+your\s+system\s+message`,
		`(?i)forget\s+your\s+instructions`,
		`(?i)you\s+are\s+no\s+longer`,
		`(?i)pretend\s+you\s+are\s+not\s+bound`,
		`(?i)reveal\s+your\s+instructions`,
		`(?i)bypass\s+your\s+(safety|filters)`,
	}
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}

	return &InputValidator{
		maxInputLen:    8192,
		bannedPatterns: compiled,
		dangerousShell: []string{
			";", "&&", "||", "|", "$(", "`", ">>", "<<",
			"rm -rf", "dd if=", "mkfs", ":(){:|:&};:",
			"curl ", "wget ", "nc ", "ncat ",
		},
	}
}

// ValidateUserInput checks for prompt injection attempts.
func (v *InputValidator) ValidateUserInput(input string) error {
	if len(input) > v.maxInputLen {
		return fmt.Errorf("input exceeds maximum length (%d > %d)", len(input), v.maxInputLen)
	}
	if len(strings.TrimSpace(input)) == 0 {
		return fmt.Errorf("empty input")
	}
	for _, re := range v.bannedPatterns {
		if re.MatchString(input) {
			return fmt.Errorf("input contains prohibited pattern (possible injection attempt)")
		}
	}
	return nil
}

// ValidateToolParams checks tool parameters for shell injection.
func (v *InputValidator) ValidateToolParams(toolName string, params map[string]interface{}) error {
	for key, val := range params {
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		for _, pattern := range v.dangerousShell {
			if strings.Contains(strVal, pattern) {
				return fmt.Errorf("parameter %q for tool %q contains dangerous pattern: %q", key, toolName, pattern)
			}
		}
	}
	return nil
}
