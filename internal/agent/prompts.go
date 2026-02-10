package agent

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/sentinel-agent/sentinel/internal/types"
)

// SystemPrompt is injected as the first message in every LLM call.
const SystemPrompt = `You are Sentinel, an autonomous Security Operations Center (SOC) AI Agent.

Your role is to analyze security incidents, investigate threats, and propose remediation actions.

## Available Tools
You have access to the following security tools:
{{.ToolDefinitions}}

## Operating Principles
1. ANALYZE before acting — gather context from logs, reputation databases, and asset inventory.
2. VALIDATE assumptions — an internal IP may belong to legitimate infrastructure.
3. PROPOSE actions with confidence scores — humans review high-risk actions.
4. EXPLAIN reasoning — all decisions must be auditable.
5. ESCALATE when uncertain — human judgment trumps automation.

## Response Format
Always structure your responses as JSON:
{
  "observation": "What you see in the incident",
  "analysis": "Your reasoning process",
  "recommendation": {
    "action": "action_type",
    "target": "target_value",
    "confidence": 0.0-1.0,
    "risk_score": 1-10,
    "reasoning": "Why this action"
  },
  "alternatives": [
    {"action": "alt_action", "risk_score": 5, "reasoning": "Why this could also work"}
  ],
  "requires_human": true/false
}

When you need more information, call the available tools to investigate.
Do not guess — investigate first, then act.
`

// ChatSystemPrompt is used for interactive chat sessions.
const ChatSystemPrompt = `You are Sentinel, an AI-powered SOC analyst assistant.
You help security operators investigate incidents, query logs, check threat intelligence, and manage defenses.

## Available Tools
{{.ToolDefinitions}}

Answer questions clearly and concisely. When you need data, call the appropriate tool.
Always explain your reasoning. If an action is risky, flag it and ask for confirmation.
`

// BuildSystemPrompt renders the system prompt with tool definitions.
func BuildSystemPrompt(promptTpl string, tools []ToolDef) string {
	var sb strings.Builder
	for _, t := range tools {
		sb.WriteString(fmt.Sprintf("- **%s**: %s\n", t.Name, t.Description))
	}

	tmpl, err := template.New("prompt").Parse(promptTpl)
	if err != nil {
		return promptTpl // fallback
	}

	var out strings.Builder
	data := map[string]string{"ToolDefinitions": sb.String()}
	if err := tmpl.Execute(&out, data); err != nil {
		return promptTpl
	}
	return out.String()
}

// BuildIncidentPrompt creates the user-message for an incident analysis request.
func BuildIncidentPrompt(incident types.Incident, matchedRules []string, context string) string {
	var sb strings.Builder
	sb.WriteString("## Incident Analysis Request\n\n")
	sb.WriteString(fmt.Sprintf("**Incident ID**: %s\n", incident.ID))
	sb.WriteString(fmt.Sprintf("**Title**: %s\n", incident.Title))
	sb.WriteString(fmt.Sprintf("**Severity**: %s\n", incident.Severity.String()))
	sb.WriteString(fmt.Sprintf("**Status**: %s\n", string(incident.Status)))
	if incident.SourceIP != "" {
		sb.WriteString(fmt.Sprintf("**Source IP**: %s\n", incident.SourceIP))
	}
	if incident.TargetUser != "" {
		sb.WriteString(fmt.Sprintf("**Target User**: %s\n", incident.TargetUser))
	}
	sb.WriteString(fmt.Sprintf("**Description**: %s\n", incident.Description))
	sb.WriteString(fmt.Sprintf("**Created**: %s\n\n", incident.CreatedAt.Format("2006-01-02 15:04:05")))

	if len(matchedRules) > 0 {
		sb.WriteString("**Matched SIGMA Rules**: ")
		sb.WriteString(strings.Join(matchedRules, ", "))
		sb.WriteString("\n\n")
	}

	if context != "" {
		sb.WriteString("## Additional Context\n")
		sb.WriteString(context)
		sb.WriteString("\n\n")
	}

	sb.WriteString("Analyze this incident. Investigate the source, assess the risk, and recommend a response action.\n")
	return sb.String()
}
