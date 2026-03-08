// Package api handles the client-side interactions with Apple's iCloud APIs.
// This file adds the Private Cloud Storage (PCS) consent flow required when
// Advanced Data Protection (ADP) is enabled for the Apple ID.
package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/rest"
)

const (
	icloudWebBase      = "https://www.icloud.com"
	setupWSBase        = "https://setup.icloud.com/setup/ws/1"
	pcsConsentTimeout  = 5 * time.Minute
	pcsPollingInterval = 5 * time.Second
)

// WebAccessState represents the ADP web access state for an account.
type WebAccessState struct {
	IsICDRSDisabled         bool `json:"isICDRSDisabled"`
	IsDeviceConsentedForPCS bool `json:"isDeviceConsentedForPCS"`
}

// PCSResponse represents the response from requestPCS.
type PCSResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// EnableConsentResponse represents the response from enableDeviceConsentForPCS.
type EnableConsentResponse struct {
	IsDeviceConsentNotificationSent bool   `json:"isDeviceConsentNotificationSent"`
	Success                         bool   `json:"success"`
	Error                           string `json:"error"`
	Message                         string `json:"message"`
}

// WebAuthToken returns the value of the X-APPLE-WEBAUTH-TOKEN cookie.
func (c *Client) WebAuthToken() string {
	return c.CookieValue("X-APPLE-WEBAUTH-TOKEN")
}

// WebAuthUser returns the value of the X-APPLE-WEBAUTH-USER cookie.
func (c *Client) WebAuthUser() string {
	if v := c.CookieValue("X-APPLE-WEBAUTH-USER"); v != "" {
		return v
	}
	return c.appleID
}

// CookieValue returns a cookie value by name.
func (c *Client) CookieValue(name string) string {
	if c.Session == nil || c.Session.Cookies == nil {
		return ""
	}
	for _, ck := range c.Session.Cookies {
		if ck != nil && ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// CookieHeaderFor builds the Cookie header for the given root URL.
func (c *Client) CookieHeaderFor(root string) string {
	u, _ := url.Parse(root)
	domainCookies, _ := GetCookiesForDomain(u, c.Session.Cookies)

	var b strings.Builder
	for _, ck := range dedupeCookiesByName(domainCookies) {
		if ck != nil && ck.Name != "" && ck.Value != "" {
			fmt.Fprintf(&b, "%s=%s; ", ck.Name, ck.Value)
		}
	}

	if strings.Contains(u.Host, "setup.icloud.com") {
		if tok := c.WebAuthToken(); tok != "" {
			fmt.Fprintf(&b, "X-APPLE-WEBAUTH-TOKEN=%s; ", tok)
		}
		if usr := c.WebAuthUser(); usr != "" {
			fmt.Fprintf(&b, "X-APPLE-WEBAUTH-USER=%s; ", usr)
		}
		if hsa := c.CookieValue("X-APPLE-WEBAUTH-HSA-LOGIN"); hsa != "" {
			fmt.Fprintf(&b, "X-APPLE-WEBAUTH-HSA-LOGIN=%s; ", hsa)
		}
	}

	return strings.TrimRight(b.String(), "; ")
}

// FetchWebBuildNumber returns the current iCloud web build number, best effort.
func (c *Client) FetchWebBuildNumber(ctx context.Context) string {
	req := &rest.Opts{
		Method:       "GET",
		RootURL:      icloudWebBase,
		Path:         "/",
		ExtraHeaders: map[string]string{uaOverrideKey: browserUA},
	}
	resp, err := c.srv.Call(ctx, req)
	if err != nil {
		fs.Debugf("icloud", "Failed to fetch web build number: %v", err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	c.Session.CaptureCookies(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fs.Debugf("icloud", "Failed to read response body for build number: %v", err)
		return ""
	}

	re := regexp.MustCompile(`data-cw-private-build-number="([^"]+)"`)
	if m := re.FindStringSubmatch(string(body)); len(m) >= 2 && m[1] != "" {
		c.webBuildNumber = m[1]
		fs.Debugf("icloud", "Discovered iCloud web build number: %s", c.webBuildNumber)
		return c.webBuildNumber
	}

	re = regexp.MustCompile(`/system/icloud\.com/([^/]+)/`)
	if m := re.FindStringSubmatch(string(body)); len(m) >= 2 && m[1] != "" {
		c.webBuildNumber = m[1]
		fs.Debugf("icloud", "Discovered iCloud web build number from asset path: %s", c.webBuildNumber)
	}
	if c.webBuildNumber == "" {
		fs.Debugf("icloud", "Could not extract build number from iCloud homepage (status %d)", resp.StatusCode)
	}
	return c.webBuildNumber
}

// DefaultSetupParams builds the default query parameters for setup.icloud.com.
func (c *Client) DefaultSetupParams(ctx context.Context) url.Values {
	p := url.Values{}
	if c.webBuildNumber == "" {
		c.webBuildNumber = c.FetchWebBuildNumber(ctx)
	}
	if c.webBuildNumber != "" {
		p.Set("clientBuildNumber", c.webBuildNumber)
		p.Set("clientMasteringNumber", c.webBuildNumber)
	}
	if c.Session != nil {
		if c.Session.ClientID != "" {
			p.Set("clientId", c.Session.ClientID)
		}
		if dsid := c.Session.DSID(); dsid != "" {
			p.Set("dsid", dsid)
		}
	}
	p.Set("requestId", uuid.NewString())
	return p
}

// SetupHeaders builds the headers required for setup.icloud.com API calls.
func (c *Client) SetupHeaders() map[string]string {
	h := GetCommonHeaders(map[string]string{
		"Referer":          icloudWebBase + "/iclouddrive/",
		"X-Requested-With": "XMLHttpRequest",
		"Origin":           icloudWebBase,
	})
	h["Cookie"] = c.CookieHeaderFor(setupWSBase)
	return h
}

// RefreshWebAuth refreshes the X-APPLE-WEBAUTH-TOKEN cookie.
func (c *Client) RefreshWebAuth(ctx context.Context) error {
	fs.Debugf("icloud", "[PCS] Refreshing web authentication token")
	headers := c.SetupHeaders()
	headers["Origin"] = icloudWebBase
	headers["Referer"] = icloudWebBase + "/"
	headers[uaOverrideKey] = browserUA
	opts := rest.Opts{
		Method:       "POST",
		RootURL:      setupWSBase,
		Path:         "/refreshWebAuth",
		ExtraHeaders: headers,
	}
	resp, err := c.RequestNoReAuth(ctx, opts, nil, nil)
	if err != nil {
		fs.Debugf("icloud", "[PCS] refreshWebAuth call failed: %v", err)
		return fmt.Errorf("refresh web auth failed: %w", err)
	}
	c.Session.CaptureCookies(resp)
	return nil
}

// BootstrapWebCookies warms up the session by visiting the main iCloud pages.
func (c *Client) BootstrapWebCookies(ctx context.Context) {
	fs.Debugf("icloud", "[PCS] Bootstrapping web cookies by visiting iCloud pages")
	commonHeaders := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		uaOverrideKey:     "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	}
	if cookie := c.CookieHeaderFor(icloudWebBase); cookie != "" {
		commonHeaders["Cookie"] = cookie
	}

	if resp, err := c.srv.Call(ctx, &rest.Opts{
		Method: "GET", RootURL: icloudWebBase, Path: "/", ExtraHeaders: commonHeaders,
	}); err == nil {
		c.Session.CaptureCookies(resp)
	}

	if resp, err := c.srv.Call(ctx, &rest.Opts{
		Method: "GET", RootURL: icloudWebBase, Path: "/iclouddrive/", ExtraHeaders: commonHeaders,
	}); err == nil {
		c.Session.CaptureCookies(resp)
	}
}

// SetupCallJSON executes a setup.icloud.com JSON request and retries once on 421.
func (c *Client) SetupCallJSON(ctx context.Context, opts rest.Opts, req, out any) (*http.Response, error) {
	opts.ExtraHeaders = c.SetupHeaders()

	resp, err := c.RequestNoReAuth(ctx, opts, req, out)
	if resp != nil {
		c.Session.CaptureCookies(resp)
	}

	if resp != nil && resp.StatusCode == 421 {
		fs.Debugf("icloud", "[PCS] Received 421 status; bootstrapping web cookies and refreshing token")
		c.BootstrapWebCookies(ctx)
		if err2 := c.RefreshWebAuth(ctx); err2 != nil {
			return nil, fmt.Errorf("failed to refresh web auth after 421 response: %w", err2)
		}

		opts.ExtraHeaders = c.SetupHeaders()
		resp, err = c.RequestNoReAuth(ctx, opts, req, out)
		if resp != nil {
			c.Session.CaptureCookies(resp)
		}
	}

	return resp, err
}

// EnsurePCSForService orchestrates the PCS consent flow when ADP is enabled.
func (c *Client) EnsurePCSForService(ctx context.Context, appName string) error {
	st, err := c.CheckWebAccessState(ctx)
	if err != nil {
		return fmt.Errorf("failed to check web access state: %w", err)
	}

	if !st.IsICDRSDisabled {
		fs.Debugf("icloud", "[PCS] ADP not active; no PCS consent required.")
		return nil
	}

	fs.Infof("icloud", "[PCS] Advanced Data Protection is active. Attempting to obtain consent from your trusted device.")
	if !st.IsDeviceConsentedForPCS {
		fs.Infof("icloud", "[PCS] Requesting approval on your trusted Apple device(s) for web access.")
		if err := c.WaitForDeviceConsent(ctx, appName); err != nil {
			return err
		}
	}

	fs.Debugf("icloud", "[PCS] Device is consented. Waiting for service cookies to be staged for %q.", appName)
	if err := c.WaitForPCSCookies(ctx, appName); err != nil {
		return err
	}

	if c.sessionSaveCallback != nil && c.Session != nil {
		c.sessionSaveCallback(c.Session)
	}

	fs.Infof("icloud", "[PCS] Successfully obtained web access for %q.", appName)
	return nil
}

// CheckWebAccessState queries iCloud for the current ADP/device-consent state.
func (c *Client) CheckWebAccessState(ctx context.Context) (*WebAccessState, error) {
	if c.WebAuthToken() == "" {
		c.BootstrapWebCookies(ctx)
		if c.WebAuthToken() == "" {
			if err := c.RefreshWebAuth(ctx); err != nil {
				fs.Debugf("icloud", "[PCS] refreshWebAuth did not produce a web auth token: %v", err)
			}
		}
	}

	opts := rest.Opts{
		Method:     "POST",
		RootURL:    setupWSBase,
		Path:       "/requestWebAccessState",
		Parameters: c.DefaultSetupParams(ctx),
	}
	var st WebAccessState
	_, err := c.SetupCallJSON(ctx, opts, nil, &st)
	if err != nil {
		return nil, fmt.Errorf("requestWebAccessState failed: %w", err)
	}
	fs.Debugf("icloud", "[PCS] Web Access State: ADP Enabled=%v, Device Consented=%v", st.IsICDRSDisabled, st.IsDeviceConsentedForPCS)
	return &st, nil
}

// EnableDeviceConsentForPCS asks a trusted device to approve web access.
func (c *Client) EnableDeviceConsentForPCS(ctx context.Context, appName string) error {
	opts := rest.Opts{
		Method:     "POST",
		RootURL:    setupWSBase,
		Path:       "/enableDeviceConsentForPCS",
		Parameters: c.DefaultSetupParams(ctx),
	}
	body := map[string]any{"appName": appName}

	var out EnableConsentResponse
	resp, err := c.SetupCallJSON(ctx, opts, body, &out)
	if err != nil {
		return fmt.Errorf("enableDeviceConsentForPCS request failed: %w", err)
	}
	if out.Error != "" {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		fs.Debugf("icloud", "[PCS] enableDeviceConsentForPCS API error: http=%d error=%q message=%q", code, out.Error, out.Message)
		return fmt.Errorf("enableDeviceConsentForPCS returned an error: %s", out.Error)
	}
	if out.IsDeviceConsentNotificationSent {
		fs.Debugf("icloud", "[PCS] Consent notification sent to trusted device(s).")
	} else {
		fs.Debugf("icloud", "[PCS] Apple did not confirm that a consent notification was sent.")
	}
	return nil
}

// RequestPCS asks iCloud to provision PCS cookies for a service.
func (c *Client) RequestPCS(ctx context.Context, appName string, derivedFromUserAction bool) (*PCSResponse, error) {
	opts := rest.Opts{
		Method:     "POST",
		RootURL:    setupWSBase,
		Path:       "/requestPCS",
		Parameters: c.DefaultSetupParams(ctx),
	}
	body := map[string]any{
		"appName":               appName,
		"derivedFromUserAction": derivedFromUserAction,
	}
	var out PCSResponse
	resp, err := c.SetupCallJSON(ctx, opts, body, &out)
	if resp != nil {
		c.Session.CaptureCookies(resp)
	}
	if err != nil {
		return nil, fmt.Errorf("requestPCS failed: %w", err)
	}
	return &out, nil
}

// WaitForDeviceConsent waits for trusted-device approval.
func (c *Client) WaitForDeviceConsent(ctx context.Context, appName string) error {
	ctx, cancel := context.WithTimeout(ctx, pcsConsentTimeout)
	defer cancel()

	if err := c.EnableDeviceConsentForPCS(ctx, appName); err != nil {
		return err
	}

	if resp, err := c.RequestPCS(ctx, appName, true); err == nil && resp.Message != "" {
		fs.Debugf("icloud", "[PCS] Initial requestPCS call status: %s", resp.Message)
	}

	ticker := time.NewTicker(pcsPollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for approval on your trusted device; please try again")
		case <-ticker.C:
			st, err := c.CheckWebAccessState(ctx)
			if err != nil {
				fs.Debugf("icloud", "[PCS] Error checking web access state during polling: %v", err)
				continue
			}
			if st.IsDeviceConsentedForPCS {
				fs.Infof("icloud", "[PCS] Approval received from trusted device.")
				return nil
			}
			_, _ = c.RequestPCS(ctx, appName, false)
			fs.Infof("icloud", "[PCS] Still waiting for approval on your trusted device...")
		}
	}
}

// WaitForPCSCookies waits until requestPCS reports that the cookies are staged.
func (c *Client) WaitForPCSCookies(ctx context.Context, appName string) error {
	ctx, cancel := context.WithTimeout(ctx, pcsConsentTimeout)
	defer cancel()

	// Even when the device is already consented, Apple appears to require an
	// initial user-action request before it starts staging the service cookies.
	if resp, err := c.RequestPCS(ctx, appName, true); err == nil && resp.Message != "" {
		fs.Debugf("icloud", "[PCS] Initial cookie staging request status: %s", resp.Message)
	}

	ticker := time.NewTicker(pcsPollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out while waiting to obtain service cookies for %s", appName)
		case <-ticker.C:
			resp, err := c.RequestPCS(ctx, appName, false)
			if err != nil {
				fs.Debugf("icloud", "[PCS] requestPCS error during polling: %v", err)
				continue
			}
			if strings.EqualFold(resp.Status, "success") {
				return nil
			}
			if resp.Message != "" {
				fs.Debugf("icloud", "[PCS] Waiting for cookies, server status: %s", resp.Message)
			}
		}
	}
}
