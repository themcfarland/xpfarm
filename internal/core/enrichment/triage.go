// LLM False-Positive Triage for Nuclei findings.
// Uses OpenAI or Anthropic API to evaluate whether a vulnerability finding is a
// true positive or likely false positive based on template info + extracted evidence.
// Only processes "pending" findings. Requires OPENAI_API_KEY or ANTHROPIC_API_KEY.
package enrichment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var triageClient = &http.Client{Timeout: 30 * time.Second}

type triageResult struct {
	verdict string // "true_positive" or "false_positive"
	reason  string
}

// TriageNucleiFindings reviews all pending vulnerability findings for targetID
// and updates their fp_status using LLM analysis. No-ops if no API key configured.
func TriageNucleiFindings(db *gorm.DB, targetID uint) {
	openaiKey := os.Getenv("OPENAI_API_KEY")
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")
	if openaiKey == "" && anthropicKey == "" {
		return
	}

	var vulns []database.Vulnerability
	db.Where("target_id = ? AND fp_status = 'pending' AND severity IN ('critical','high','medium')", targetID).Find(&vulns)
	if len(vulns) == 0 {
		return
	}

	triaged := 0
	fps := 0
	for _, v := range vulns {
		result, err := callTriageLLM(v, openaiKey, anthropicKey)
		if err != nil {
			utils.LogDebug("[Triage] LLM call failed for %s: %v", v.TemplateID, err)
			continue
		}
		db.Model(&v).Updates(map[string]interface{}{
			"fp_status": result.verdict,
			"fp_reason": result.reason,
		})
		triaged++
		if result.verdict == "false_positive" {
			fps++
			utils.LogDebug("[Triage] FP: %s — %s", v.TemplateID, result.reason)
		}
	}
	if triaged > 0 {
		utils.LogSuccess("[Triage] Triaged %d findings for target %d (%d FPs filtered)", triaged, targetID, fps)
	}
}

func buildTriagePrompt(v database.Vulnerability) string {
	var sb strings.Builder
	sb.WriteString("You are a senior penetration tester reviewing a vulnerability scanner finding.\n")
	sb.WriteString("Determine if this finding is a TRUE POSITIVE or FALSE POSITIVE.\n\n")
	sb.WriteString(fmt.Sprintf("Template: %s\n", v.TemplateID))
	sb.WriteString(fmt.Sprintf("Name: %s\n", v.Name))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", v.Severity))
	if v.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", v.Description))
	}
	if v.MatcherName != "" {
		sb.WriteString(fmt.Sprintf("Matcher: %s\n", v.MatcherName))
	}
	if v.Extracted != "" {
		extracted := v.Extracted
		if len(extracted) > 500 {
			extracted = extracted[:500] + "..."
		}
		sb.WriteString(fmt.Sprintf("Extracted Evidence: %s\n", extracted))
	}
	sb.WriteString("\nRespond in JSON only:\n")
	sb.WriteString(`{"verdict": "true_positive" | "false_positive", "reason": "<one sentence>"}`)
	return sb.String()
}

func callTriageLLM(v database.Vulnerability, openaiKey, anthropicKey string) (*triageResult, error) {
	prompt := buildTriagePrompt(v)

	if openaiKey != "" {
		return triageWithOpenAI(prompt, openaiKey)
	}
	return triageWithAnthropic(prompt, anthropicKey)
}

func triageWithOpenAI(prompt, apiKey string) (*triageResult, error) {
	payload := map[string]interface{}{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":  150,
		"temperature": 0,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := triageClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return parseTriageJSON(result.Choices[0].Message.Content)
}

func triageWithAnthropic(prompt, apiKey string) (*triageResult, error) {
	payload := map[string]interface{}{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 150,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := triageClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Content) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return parseTriageJSON(result.Content[0].Text)
}

func parseTriageJSON(raw string) (*triageResult, error) {
	// Extract JSON from possible surrounding text
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 {
		return nil, fmt.Errorf("no JSON in response: %s", raw)
	}
	raw = raw[start : end+1]

	var parsed struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, err
	}
	if parsed.Verdict != "true_positive" && parsed.Verdict != "false_positive" {
		parsed.Verdict = "true_positive" // default to TP on ambiguity
	}
	return &triageResult{verdict: parsed.Verdict, reason: parsed.Reason}, nil
}
