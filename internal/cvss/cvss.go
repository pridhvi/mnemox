package cvss

import (
	"fmt"
	"strings"

	gocvss40 "github.com/pandatix/go-cvss/40"
)

var BaseMetricOrder = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

var BaseMetricValues = map[string][]string{
	"AV": {"N", "A", "L", "P"},
	"AC": {"L", "H"},
	"AT": {"N", "P"},
	"PR": {"N", "L", "H"},
	"UI": {"N", "P", "A"},
	"VC": {"H", "L", "N"},
	"VI": {"H", "L", "N"},
	"VA": {"H", "L", "N"},
	"SC": {"H", "L", "N"},
	"SI": {"H", "L", "N"},
	"SA": {"H", "L", "N"},
}

var MetricNames = map[string]string{
	"AV": "Attack Vector",
	"AC": "Attack Complexity",
	"AT": "Attack Requirements",
	"PR": "Privileges Required",
	"UI": "User Interaction",
	"VC": "Vulnerable System Confidentiality",
	"VI": "Vulnerable System Integrity",
	"VA": "Vulnerable System Availability",
	"SC": "Subsequent System Confidentiality",
	"SI": "Subsequent System Integrity",
	"SA": "Subsequent System Availability",
}

type Result struct {
	Vector   string
	Score    float64
	Severity string
	Metrics  map[string]string
}

func FromMetrics(metrics map[string]string) (Result, error) {
	parts := []string{"CVSS:4.0"}
	for _, key := range BaseMetricOrder {
		value := strings.ToUpper(metrics[key])
		if value == "" {
			return Result{}, fmt.Errorf("missing CVSS metric %s", key)
		}
		if !validValue(key, value) {
			return Result{}, fmt.Errorf("invalid %s value %q", key, value)
		}
		parts = append(parts, key+":"+value)
	}
	return FromVector(strings.Join(parts, "/"))
}

func FromVector(vector string) (Result, error) {
	parsed, err := gocvss40.ParseVector(vector)
	if err != nil {
		return Result{}, err
	}
	score := parsed.Score()
	severity, err := gocvss40.Rating(score)
	if err != nil {
		return Result{}, err
	}
	metrics := make(map[string]string, len(BaseMetricOrder))
	for _, key := range BaseMetricOrder {
		value, err := parsed.Get(key)
		if err != nil {
			return Result{}, err
		}
		metrics[key] = value
	}
	return Result{Vector: parsed.Vector(), Score: score, Severity: severity, Metrics: metrics}, nil
}

func validValue(metric, value string) bool {
	for _, candidate := range BaseMetricValues[metric] {
		if candidate == value {
			return true
		}
	}
	return false
}
