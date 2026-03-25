// Vision enricher: uses a vision-capable LLM (OpenAI GPT-4o or Anthropic Claude)
// to analyze Gowitness screenshots and extract security-relevant intelligence.
//
// For each WebAsset with a screenshot, it identifies:
//   - Login panels and authentication prompts
//   - Admin interfaces and dashboards (Grafana, Jenkins, Kibana, etc.)
//   - Exposed sensitive data (stack traces, credentials, tokens)
//   - Technology fingerprints visible in the UI
//   - Overall security interest summary
//
// Cost: ~$0.002/screenshot with GPT-4o or claude-haiku-4-5-20251001.
// Requires OPENAI_API_KEY or ANTHROPIC_API_KEY to be set.
package enrichment

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var visionClient = &http.Client{Timeout: 30 * time.Second}

const visionPrompt = `You are a security analyst reviewing a web application screenshot.
Analyze this screenshot and return a single compact JSON object with these fields:
{
  "auth_required": true/false,
  "admin_panel": true/false,
  "technologies": ["list of visible technologies/frameworks"],
  "sensitive_data": true/false,
  "sensitive_detail": "brief description of any sensitive data visible, or empty string",
  "summary": "one sentence security-relevant observation",
  "tags": ["login","admin","dashboard","grafana","jenkins","kibana","debug","error","default-creds","404","blank"]
}
Return only valid JSON with no markdown formatting.`

// AnalyzeScreenshots processes all WebAssets for targetID that have screenshots
// but no vision analysis yet. Respects EnableVisionAnalysis profile toggle.
func AnalyzeScreenshots(db *gorm.DB, targetID uint) {
	var assets []database.WebAsset
	db.Where("target_id = ? AND screenshot_path != '' AND vision_analysis = ''", targetID).Find(&assets)
	if len(assets) == 0 {
		return
	}

	provider, apiKey := detectVisionProvider()
	if provider == "" {
		return
	}

	utils.LogInfo("[Vision] Analyzing %d screenshots for target %d using %s", len(assets), targetID, provider)

	for i := range assets {
		analysis, err := analyzeOne(assets[i].Screenshot, provider, apiKey)
		if err != nil {
			utils.LogDebug("[Vision] Failed to analyze %s: %v", assets[i].URL, err)
			continue
		}
		if analysis == "" {
			continue
		}
		db.Model(&assets[i]).Update("vision_analysis", analysis)
		utils.LogDebug("[Vision] Analyzed screenshot for %s: %s", assets[i].URL, truncate(analysis, 80))

		// Small delay between calls to avoid rate limits
		time.Sleep(200 * time.Millisecond)
	}
}

func detectVisionProvider() (provider, apiKey string) {
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return "openai", key
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return "anthropic", key
	}
	return "", ""
}

func analyzeOne(screenshotPath, provider, apiKey string) (string, error) {
	imgData, err := os.ReadFile(screenshotPath)
	if err != nil {
		return "", fmt.Errorf("read screenshot: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(imgData)
	mediaType := "image/png"
	if strings.HasSuffix(strings.ToLower(screenshotPath), ".jpg") ||
		strings.HasSuffix(strings.ToLower(screenshotPath), ".jpeg") {
		mediaType = "image/jpeg"
	}

	switch provider {
	case "openai":
		return analyzeOpenAI(b64, mediaType, apiKey)
	case "anthropic":
		return analyzeAnthropic(b64, mediaType, apiKey)
	}
	return "", fmt.Errorf("unknown provider: %s", provider)
}

// --- OpenAI GPT-4o Vision ---

type openAIRequest struct {
	Model    string        `json:"model"`
	Messages []openAIMsg   `json:"messages"`
	MaxTokens int          `json:"max_tokens"`
}

type openAIMsg struct {
	Role    string        `json:"role"`
	Content []interface{} `json:"content"`
}

func analyzeOpenAI(b64, mediaType, apiKey string) (string, error) {
	body := openAIRequest{
		Model:     "gpt-4o",
		MaxTokens: 400,
		Messages: []openAIMsg{
			{
				Role: "user",
				Content: []interface{}{
					map[string]interface{}{
						"type": "image_url",
						"image_url": map[string]string{
							"url":    fmt.Sprintf("data:%s;base64,%s", mediaType, b64),
							"detail": "low",
						},
					},
					map[string]string{
						"type": "text",
						"text": visionPrompt,
					},
				},
			},
		},
	}

	return callVisionAPI("https://api.openai.com/v1/chat/completions",
		"Bearer "+apiKey, body,
		func(respBody []byte) (string, error) {
			var r struct {
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}
			if err := json.Unmarshal(respBody, &r); err != nil {
				return "", err
			}
			if len(r.Choices) == 0 {
				return "", fmt.Errorf("no choices in response")
			}
			return r.Choices[0].Message.Content, nil
		})
}

// --- Anthropic Claude Vision ---

func analyzeAnthropic(b64, mediaType, apiKey string) (string, error) {
	body := map[string]interface{}{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 400,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "image",
						"source": map[string]string{
							"type":       "base64",
							"media_type": mediaType,
							"data":       b64,
						},
					},
					{
						"type": "text",
						"text": visionPrompt,
					},
				},
			},
		},
	}

	return callVisionAPI("https://api.anthropic.com/v1/messages",
		apiKey, body,
		func(respBody []byte) (string, error) {
			var r struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			if err := json.Unmarshal(respBody, &r); err != nil {
				return "", err
			}
			for _, c := range r.Content {
				if c.Type == "text" {
					return c.Text, nil
				}
			}
			return "", fmt.Errorf("no text content in response")
		})
}

func callVisionAPI(endpoint, authValue string, body interface{}, parse func([]byte) (string, error)) (string, error) {
	reqJSON, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(reqJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Handle both "Bearer xxx" and raw key (Anthropic uses "x-api-key")
	if strings.HasPrefix(authValue, "Bearer ") {
		req.Header.Set("Authorization", authValue)
	} else {
		req.Header.Set("x-api-key", authValue)
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	resp, err := visionClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	return parse(respBody)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
