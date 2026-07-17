// Package tplink implements the TP-Link router web-UI request/response
// protocol: the keys/auth bootstrap, the encrypted login, and encrypted
// authenticated requests with transparent re-login on session timeout.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

// debug enables verbose request/response logging via TPLINK_DEBUG=1.
var debug = os.Getenv("TPLINK_DEBUG") == "1"

// Config holds connection + credential settings.
type Config struct {
	Host     string // e.g. "192.168.0.1"
	Username string // login hash uses username+password; usually "admin"
	Password string
	RGSec    bool // true -> SHA-256 credential hash instead of MD5
	Force    bool // true -> always send confirm=true to evict an existing session
}

// Client drives the protocol and owns the negotiated session state.
type Client struct {
	cfg  Config
	http *http.Client

	// session state, set by login() and reused for every request
	stok    string
	aesKey  string
	aesIV   string
	pwdHash string
	signKey *PublicKey
	seq     int
}

// apiResponse is the envelope every router endpoint returns.
type apiResponse struct {
	Success   bool            `json:"success"`
	ErrorCode string          `json:"errorcode"`
	Data      json.RawMessage `json:"data"`
}

// New creates a client. A cookie jar is REQUIRED: the router sets a session
// cookie during keys/auth that must be echoed back on login (mirrors the
// browser's XMLHttpRequest, which carries cookies automatically). Without it,
// login returns an empty body.
func NewClient(cfg Config) *Client {
	if cfg.Username == "" {
		cfg.Username = "admin"
	}
	jar, _ := cookiejar.New(nil)
	return &Client{cfg: cfg, http: &http.Client{Jar: jar}}
}

func (c *Client) base() string {
	return fmt.Sprintf("http://%s/cgi-bin/luci/;stok=", c.cfg.Host)
}

// signDataBody builds "sign=<sign>&data=<data>" in that exact order, which the
// router requires (see postForm).
func signDataBody(sign, data string) string {
	return "sign=" + url.QueryEscape(sign) + "&data=" + url.QueryEscape(data)
}

// postForm sends a POST with x-www-form-urlencoded body and decodes the
// JSON envelope. stok is spliced into the path as the JS does.
//
// body must be a pre-encoded form string. Field ORDER is significant: the
// router rejects login/request bodies with HTTP 403 unless "sign" precedes
// "data" (url.Values.Encode would sort them the wrong way round).
func (c *Client) postForm(stok, path, body string) (*apiResponse, error) {
	endpoint := c.base() + stok + path
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/", c.cfg.Host))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[debug] POST %s -> %d (%d bytes): %.300s\n",
			path, resp.StatusCode, len(respBody), respBody)
	}
	var out apiResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode %s: HTTP %d, %w (body: %.200s)", path, resp.StatusCode, err, respBody)
	}
	return &out, nil
}

// getKeys fetches the 1024-bit password RSA key (POST /login?form=keys).
func (c *Client) getKeys() (*PublicKey, error) {
	resp, err := c.postForm("", "/login?form=keys", "operation=read")
	if err != nil {
		return nil, err
	}
	var d struct {
		Password []string `json:"password"`
	}
	if err := json.Unmarshal(resp.Data, &d); err != nil || len(d.Password) != 2 {
		return nil, fmt.Errorf("unexpected form=keys data: %s", resp.Data)
	}
	return ParsePublicKey(d.Password[0], d.Password[1])
}

// getAuth fetches the 512-bit signature RSA key and sequence number
// (POST /login?form=auth).
func (c *Client) getAuth() (*PublicKey, int, error) {
	resp, err := c.postForm("", "/login?form=auth", "operation=read")
	if err != nil {
		return nil, 0, err
	}
	var d struct {
		Key []string `json:"key"`
		Seq int      `json:"seq"`
	}
	if err := json.Unmarshal(resp.Data, &d); err != nil || len(d.Key) != 2 {
		return nil, 0, fmt.Errorf("unexpected form=auth data: %s", resp.Data)
	}
	pk, err := ParsePublicKey(d.Key[0], d.Key[1])
	return pk, d.Seq, err
}

// Login runs the full handshake and stores the session state. If the router
// reports a session conflict it automatically retries once with confirm=true
// (the "Login here" / force-takeover path), unless cfg.Force already forced it.
func (c *Client) Login() error {
	err := c.attemptLogin(c.cfg.Force)
	var ce *conflictError
	if errorsAsConflict(err, &ce) && !c.cfg.Force {
		if debug {
			fmt.Fprintf(os.Stderr, "[debug] session conflict (%s) — retrying with confirm=true\n", ce.code)
		}
		return c.attemptLogin(true)
	}
	return err
}

// attemptLogin performs one login. When force is true, the inner body carries
// confirm=true, instructing the router to terminate any existing session.
func (c *Client) attemptLogin(force bool) error {
	pwdKey, err := c.getKeys()
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	signKey, seq, err := c.getAuth()
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	aesKey, err := RandDigits(16)
	if err != nil {
		return err
	}
	aesIV, err := RandDigits(16)
	if err != nil {
		return err
	}

	encPwd, err := pwdKey.EncryptChunked(c.cfg.Password)
	if err != nil {
		return fmt.Errorf("rsa password: %w", err)
	}
	body := "operation=login&password=" + encPwd
	if force {
		body = "operation=login&confirm=true&password=" + encPwd
	}
	data, err := AESEncryptB64(body, aesKey, aesIV)
	if err != nil {
		return err
	}
	pwdHash := HashCredential(c.cfg.Username, c.cfg.Password, c.cfg.RGSec)

	sigText := fmt.Sprintf("k=%s&i=%s&h=%s&s=%d", aesKey, aesIV, pwdHash, seq+len(data))
	sign, err := signKey.EncryptChunked(sigText)
	if err != nil {
		return fmt.Errorf("rsa sign: %w", err)
	}

	resp, err := c.postForm("", "/login?form=login", signDataBody(sign, data))
	if err != nil {
		return err
	}

	// The login response is AES-encrypted under our session key; decrypt it.
	plain, err := decryptPayload(resp.Data, aesKey, aesIV)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	var parsed struct {
		Success   bool   `json:"success"`
		ErrorCode string `json:"errorcode"`
		Data      struct {
			Stok      string `json:"stok"`
			ErrorCode string `json:"errorcode"`
		} `json:"data"`
	}
	_ = json.Unmarshal(plain, &parsed)

	if parsed.Data.Stok != "" {
		c.stok, c.aesKey, c.aesIV = parsed.Data.Stok, aesKey, aesIV
		c.pwdHash, c.signKey, c.seq = pwdHash, signKey, seq
		return nil
	}
	if isConflictCode(parsed.ErrorCode) || isConflictCode(parsed.Data.ErrorCode) {
		return &conflictError{code: firstNonEmpty(parsed.ErrorCode, parsed.Data.ErrorCode)}
	}
	return fmt.Errorf("login failed: errorcode=%q (%s)", parsed.ErrorCode, plain)
}

// decryptPayload returns the plaintext JSON of an envelope's data field, which
// the router sends as an AES-encrypted base64 string under the session key.
func decryptPayload(raw json.RawMessage, aesKey, aesIV string) ([]byte, error) {
	var asString string
	if json.Unmarshal(raw, &asString) == nil && asString != "" {
		dec, err := AESDecryptB64(asString, aesKey, aesIV)
		if err != nil {
			return nil, fmt.Errorf("decrypt payload: %w", err)
		}
		return []byte(dec), nil
	}
	return []byte(raw), nil // already plaintext JSON
}

// conflictError signals that login was refused because another admin session
// is active ("user conflict"); the caller may retry with confirm=true.
type conflictError struct{ code string }

func (e *conflictError) Error() string { return "session conflict: " + e.code }

func errorsAsConflict(err error, target **conflictError) bool {
	for err != nil {
		if ce, ok := err.(*conflictError); ok {
			*target = ce
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func isConflictCode(code string) bool {
	switch strings.ToLower(code) {
	case "user conflict", "-5212", "-5002conflict":
		return true
	}
	return strings.Contains(strings.ToLower(code), "conflict")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Request makes an authenticated, AES-encrypted call and returns the decrypted
// JSON. On a session-timeout style error it logs in again once and retries.
func (c *Client) Request(path string, fields url.Values) (json.RawMessage, error) {
	if c.stok == "" {
		if err := c.Login(); err != nil {
			return nil, err
		}
	}
	out, err := c.requestOnce(path, fields)
	if err == nil {
		return out, nil
	}
	if !isSessionError(err) {
		return nil, err
	}
	// session expired / evicted -> fresh handshake, retry once
	if err := c.Login(); err != nil {
		return nil, fmt.Errorf("relogin after %v: %w", err, err)
	}
	return c.requestOnce(path, fields)
}

func (c *Client) requestOnce(path string, fields url.Values) (json.RawMessage, error) {
	body := fields.Encode()
	data, err := AESEncryptB64(body, c.aesKey, c.aesIV)
	if err != nil {
		return nil, err
	}
	// post-login signature carries only hash + seq (no AES key)
	sigText := fmt.Sprintf("h=%s&s=%d", c.pwdHash, c.seq+len(data))
	sign, err := c.signKey.EncryptChunked(sigText)
	if err != nil {
		return nil, err
	}

	resp, err := c.postForm(c.stok, path, signDataBody(sign, data))
	if err != nil {
		return nil, err
	}
	if !resp.Success && resp.ErrorCode != "" {
		return nil, &sessionError{code: resp.ErrorCode}
	}

	// response data is AES ciphertext under our session key
	var asString string
	if json.Unmarshal(resp.Data, &asString) == nil && asString != "" {
		dec, err := AESDecryptB64(asString, c.aesKey, c.aesIV)
		if err != nil {
			return nil, fmt.Errorf("decrypt response: %w", err)
		}
		return json.RawMessage(dec), nil
	}
	return resp.Data, nil
}

// Stok exposes the current session token (for logging/debug).
func (c *Client) Stok() string { return c.stok }

type sessionError struct{ code string }

func (e *sessionError) Error() string { return "session error: " + e.code }

func isSessionError(err error) bool {
	var se *sessionError
	if !errorsAs(err, &se) {
		return false
	}
	switch se.code {
	case "timeout", "user conflict", "permission denied", "exceeded max", "-40101":
		return true
	}
	return false
}

// errorsAs is a tiny shim to avoid importing errors just for As in one place.
func errorsAs(err error, target **sessionError) bool {
	for err != nil {
		if se, ok := err.(*sessionError); ok {
			*target = se
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
