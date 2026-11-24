// Package webdriver is a minimal W3C WebDriver client for geckodriver
// (test-only). It supports what the browser tests need: sessions, add-on
// install, navigation, scripts in content and chrome context, and windows.
package webdriver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Session struct {
	Base string // e.g. http://127.0.0.1:4444
	ID   string
	hc   *http.Client
}

type wdError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	Stacktrace string `json:"stacktrace"`
}

func (s *Session) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	url := s.Base + path
	if s.ID != "" && path != "/session" {
		url = s.Base + "/session/" + s.ID + path
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var env struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("webdriver %s %s: %d %s", method, path, resp.StatusCode, data)
	}
	if resp.StatusCode >= 400 {
		var e wdError
		json.Unmarshal(env.Value, &e)
		return fmt.Errorf("webdriver %s %s: %s: %s", method, path, e.Error, e.Message)
	}
	if out != nil {
		return json.Unmarshal(env.Value, out)
	}
	return nil
}

// New starts a session with the given Firefox options.
func New(base string, firefoxOptions map[string]any) (*Session, error) {
	s := &Session{Base: base, hc: &http.Client{Timeout: 120 * time.Second}}
	var out struct {
		SessionID string `json:"sessionId"`
	}
	caps := map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{
		"browserName":        "firefox",
		"acceptInsecureCerts": true,
		"pageLoadStrategy":   "normal",
		"moz:firefoxOptions": firefoxOptions,
		"timeouts":           map[string]any{"pageLoad": 45000, "script": 30000},
	}}}
	if err := s.do("POST", "/session", caps, &out); err != nil {
		return nil, err
	}
	s.ID = out.SessionID
	return s, nil
}

func (s *Session) Close() error { return s.do("DELETE", "", nil, nil) }

// InstallAddon installs an .xpi or unpacked directory as a temporary add-on.
func (s *Session) InstallAddon(path string) (string, error) {
	var id string
	err := s.do("POST", "/moz/addon/install", map[string]any{"path": path, "temporary": true}, &id)
	return id, err
}

// SetContext switches between "content" and "chrome".
func (s *Session) SetContext(ctx string) error {
	return s.do("POST", "/moz/context", map[string]any{"context": ctx}, nil)
}

func (s *Session) Navigate(url string) error {
	return s.do("POST", "/url", map[string]any{"url": url}, nil)
}

func (s *Session) Source() (string, error) {
	var out string
	err := s.do("GET", "/source", nil, &out)
	return out, err
}

func (s *Session) URL() (string, error) {
	var out string
	err := s.do("GET", "/url", nil, &out)
	return out, err
}

// Exec runs a synchronous script; the result is decoded into out.
func (s *Session) Exec(script string, args []any, out any) error {
	if args == nil {
		args = []any{}
	}
	return s.do("POST", "/execute/sync", map[string]any{"script": script, "args": args}, out)
}

// ExecAsync runs an async script (the last argument is the callback).
func (s *Session) ExecAsync(script string, args []any, out any) error {
	if args == nil {
		args = []any{}
	}
	return s.do("POST", "/execute/async", map[string]any{"script": script, "args": args}, out)
}

func (s *Session) Handles() ([]string, error) {
	var out []string
	err := s.do("GET", "/window/handles", nil, &out)
	return out, err
}

func (s *Session) Handle() (string, error) {
	var out string
	err := s.do("GET", "/window", nil, &out)
	return out, err
}

func (s *Session) SwitchTo(handle string) error {
	return s.do("POST", "/window", map[string]any{"handle": handle}, nil)
}

func (s *Session) CloseWindow() error { return s.do("DELETE", "/window", nil, nil) }

// NewTab opens a new tab and returns its handle.
func (s *Session) NewTab() (string, error) {
	var out struct {
		Handle string `json:"handle"`
	}
	err := s.do("POST", "/window/new", map[string]any{"type": "tab"}, &out)
	return out.Handle, err
}

// Find returns an element id for a CSS selector.
func (s *Session) Find(css string) (string, error) {
	var out map[string]string
	if err := s.do("POST", "/element", map[string]any{"using": "css selector", "value": css}, &out); err != nil {
		return "", err
	}
	for _, v := range out {
		return v, nil
	}
	return "", fmt.Errorf("no element id")
}

func (s *Session) Click(el string) error {
	return s.do("POST", "/element/"+el+"/click", map[string]any{}, nil)
}

func (s *Session) Text(el string) (string, error) {
	var out string
	err := s.do("GET", "/element/"+el+"/text", nil, &out)
	return out, err
}
