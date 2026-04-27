package agents

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// ntfyProvider implements Provider for ntfy push notifications.
// ntfy publishes messages via HTTP POST to a topic URL of the form
// <server>/<topic> (e.g. https://ntfy.sh/my-alerts or
// http://192.168.1.x:9090/clonarr). Messages are sent as Markdown
// with a severity-mapped priority header:
//
//   - SeverityCritical → priority 5 (urgent — persistent, can wake device)
//   - SeverityWarning  → priority 3 (default)
//   - SeverityInfo     → priority 3 (default)
//
// Security: ntfy is primarily self-hosted on private LAN addresses, so HTTP
// calls go through Runtime.NotifyClient (standard client) rather than
// Runtime.SafeClient (SSRF-protected). SafeClient's blocklist rejects
// RFC-1918 addresses, which would prevent self-hosted deployments from
// working. This matches the same trust model used by the Gotify provider.
type ntfyProvider struct{}

// Compile-time check: ntfyProvider satisfies the Provider interface.
var _ Provider = ntfyProvider{}

func init() {
	registerProvider(ntfyProvider{})
}

// Type returns the provider registration key used in Agent.Type.
func (ntfyProvider) Type() string {
	return "ntfy"
}

// Async returns true because ntfy sends are dispatched in background workers.
func (ntfyProvider) Async() bool {
	return true
}

// MaskConfig hides the ntfy access token for API responses.
// NtfyTopicURL is not a bearer credential and is returned as-is.
func (ntfyProvider) MaskConfig(cfg Config) Config {
	cfg.NtfyToken = maskSecret(cfg.NtfyToken, maskedToken)
	return cfg
}

// PreserveConfig keeps the existing token when the masked placeholder is posted back.
func (ntfyProvider) PreserveConfig(incoming, existing Config) Config {
	incoming.NtfyToken = preserveIfMasked(strings.TrimSpace(incoming.NtfyToken), existing.NtfyToken, maskedToken)
	return incoming
}

// Validate checks that the required NtfyTopicURL field is present and uses a
// recognised URL scheme. NtfyToken is intentionally optional — unauthenticated
// self-hosted servers require no credentials.
func (ntfyProvider) Validate(agent Agent) error {
	u := strings.TrimSpace(agent.Config.NtfyTopicURL)
	if u == "" {
		return fmt.Errorf("ntfy topic URL is required")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("ntfy topic URL must start with http:// or https://")
	}
	return nil
}

// Test sends a verification message to the configured ntfy topic.
// A top-level error is returned only for invalid configuration; HTTP-level
// failures (non-2xx, network errors) are captured in the returned TestResult.
func (ntfyProvider) Test(ctx context.Context, runtime Runtime, agent Agent) ([]TestResult, error) {
	cfg := agent.Config
	if strings.TrimSpace(cfg.NtfyTopicURL) == "" {
		return nil, fmt.Errorf("ntfy topic URL is required")
	}
	if runtime.NotifyClient == nil {
		return nil, fmt.Errorf("ntfy client not configured")
	}

	res := TestResult{Label: "Ntfy", Status: statusOK}
	resp, err := ntfyPost(ctx, runtime.NotifyClient, cfg, testTitle, testMessage("Ntfy"), ntfyPriority(SeverityInfo))
	if err != nil {
		res.Status = statusError
		res.Error = fmt.Sprintf("Failed to reach ntfy: %v", err)
		return []TestResult{res}, nil
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 400 {
		res.Status = statusError
		res.Error = httpError("ntfy", resp).Error()
	}

	return []TestResult{res}, nil
}

// Notify delivers one outbound ntfy message with severity-mapped priority.
// Returns nil (skip) when the topic URL is empty, which can occur if the
// agent was disabled or misconfigured after dispatch was already queued.
func (ntfyProvider) Notify(ctx context.Context, runtime Runtime, agent Agent, payload Payload) error {
	cfg := agent.Config
	if strings.TrimSpace(cfg.NtfyTopicURL) == "" {
		return nil
	}
	if runtime.NotifyClient == nil {
		return fmt.Errorf("ntfy client not configured")
	}

	resp, err := ntfyPost(ctx, runtime.NotifyClient, cfg, payload.Title, payload.Message, ntfyPriority(payload.Severity))
	if err != nil {
		return err
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 400 {
		return httpError("ntfy", resp)
	}

	return nil
}

// ntfyPost builds and sends one ntfy HTTP message. This helper deduplicates
// the identical request construction shared by Test and Notify.
// Messages are sent as plain text with the Markdown header enabled so that
// formatted bodies render correctly in ntfy clients.
func ntfyPost(ctx context.Context, client HTTPPoster, cfg Config, title, message, priority string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(cfg.NtfyTopicURL), bytes.NewBufferString(message))
	if err != nil {
		return nil, fmt.Errorf("ntfy build request: %w", err)
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Markdown", "yes")
	if token := strings.TrimSpace(cfg.NtfyToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}

// ntfyPriority maps Clonarr severity levels to ntfy priority integers (1–5).
// ntfy priority reference:
//
//   - 5 (urgent)  — persistent notification, max vibration, can wake the device
//   - 3 (default) — standard notification behaviour
//
// Mapping:
//
//   - SeverityCritical → "5" (urgent — sync failures requiring immediate attention)
//   - SeverityWarning  → "3" (default — cleanup and changelog events)
//   - SeverityInfo     → "3" (default — routine auto-sync success)
func ntfyPriority(severity Severity) string {
	if severity == SeverityCritical {
		return "5"
	}
	return "3"
}
