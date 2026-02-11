package platform

import (
	"net"
	"strings"

	"github.com/sentinel-agent/sentinel/internal/types"
)

// FieldMapping maps a source-specific field name to the normalized field name.
type FieldMapping struct {
	SourceField string
	NormField   string
}

// Normalizer enriches LogEvent.Fields with standard field names.
type Normalizer struct {
	// mappings maps source type → list of field mappings.
	mappings map[string][]FieldMapping
}

// NewNormalizer creates a normalizer with default ECS-inspired mappings.
func NewNormalizer() *Normalizer {
	n := &Normalizer{
		mappings: make(map[string][]FieldMapping),
	}

	// Common mappings applied to all sources.
	n.mappings["_common"] = []FieldMapping{
		{SourceField: "src_ip", NormField: "source_ip"},
		{SourceField: "srcip", NormField: "source_ip"},
		{SourceField: "source_address", NormField: "source_ip"},
		{SourceField: "remote_addr", NormField: "source_ip"},
		{SourceField: "client_ip", NormField: "source_ip"},
		{SourceField: "dst_ip", NormField: "dest_ip"},
		{SourceField: "dstip", NormField: "dest_ip"},
		{SourceField: "destination_address", NormField: "dest_ip"},
		{SourceField: "user", NormField: "username"},
		{SourceField: "account_name", NormField: "username"},
		{SourceField: "login", NormField: "username"},
		{SourceField: "src_port", NormField: "source_port"},
		{SourceField: "dst_port", NormField: "dest_port"},
		{SourceField: "proto", NormField: "protocol"},
	}

	// Windows Event Log specific mappings.
	n.mappings["eventlog"] = []FieldMapping{
		{SourceField: "event_id", NormField: "event_id"},
		{SourceField: "level", NormField: "event_level"},
		{SourceField: "source_network_address", NormField: "source_ip"},
		{SourceField: "target_user_name", NormField: "username"},
		{SourceField: "process_name", NormField: "process.name"},
		{SourceField: "process_id", NormField: "pid"},
	}

	// Linux syslog/journald specific mappings.
	n.mappings["journald"] = []FieldMapping{
		{SourceField: "unit", NormField: "service"},
		{SourceField: "_COMM", NormField: "process.name"},
		{SourceField: "_PID", NormField: "pid"},
		{SourceField: "_UID", NormField: "uid"},
	}

	return n
}

// AddMapping adds a custom field mapping for a source type.
func (n *Normalizer) AddMapping(sourceType, sourceField, normField string) {
	n.mappings[sourceType] = append(n.mappings[sourceType], FieldMapping{
		SourceField: sourceField,
		NormField:   normField,
	})
}

// Normalize enriches the event's Fields map with standardized field names.
// Original fields are preserved; normalized fields are added alongside them.
func (n *Normalizer) Normalize(event *types.LogEvent) {
	if event.Fields == nil {
		event.Fields = make(map[string]string)
	}

	// Apply common mappings.
	n.applyMappings(event, "_common")

	// Apply source-specific mappings based on the event source.
	sourceType := n.detectSourceType(event)
	if sourceType != "" {
		n.applyMappings(event, sourceType)
	}

	// Enrich with derived fields.
	n.enrichDerived(event)
}

func (n *Normalizer) applyMappings(event *types.LogEvent, sourceType string) {
	mappings, ok := n.mappings[sourceType]
	if !ok {
		return
	}

	for _, m := range mappings {
		if val, exists := event.Fields[m.SourceField]; exists {
			// Don't overwrite existing normalized fields.
			if _, alreadySet := event.Fields[m.NormField]; !alreadySet {
				event.Fields[m.NormField] = val
			}
			// Also set the dotted form as a flat key (e.g., "process.name").
			if strings.Contains(m.NormField, ".") {
				flat := strings.ReplaceAll(m.NormField, ".", "_")
				if _, alreadySet := event.Fields[flat]; !alreadySet {
					event.Fields[flat] = val
				}
			}
		}
	}
}

func (n *Normalizer) detectSourceType(event *types.LogEvent) string {
	if strings.HasPrefix(event.Source, "eventlog") {
		return "eventlog"
	}
	if event.Source == "journald" || event.Source == "syslog" {
		return "journald"
	}
	return ""
}

// enrichDerived adds computed fields based on existing data.
func (n *Normalizer) enrichDerived(event *types.LogEvent) {
	// If source_ip is present, determine if it's internal/external.
	if ip := event.Fields["source_ip"]; ip != "" {
		parsed := net.ParseIP(ip)
		if parsed != nil {
			if isPrivateIP(parsed) {
				event.Fields["source_ip_type"] = "internal"
			} else {
				event.Fields["source_ip_type"] = "external"
			}
		}
	}
}

// isPrivateIP checks if an IP is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupField performs dotted field lookup (e.g., "process.name").
// It checks: exact match, dotted form, underscore form.
func LookupField(fields map[string]string, name string) (string, bool) {
	// Direct lookup.
	if val, ok := fields[name]; ok {
		return val, true
	}

	// Try replacing dots with underscores.
	if strings.Contains(name, ".") {
		flat := strings.ReplaceAll(name, ".", "_")
		if val, ok := fields[flat]; ok {
			return val, true
		}
	}

	// Try replacing underscores with dots.
	if strings.Contains(name, "_") {
		dotted := strings.ReplaceAll(name, "_", ".")
		if val, ok := fields[dotted]; ok {
			return val, true
		}
	}

	return "", false
}
