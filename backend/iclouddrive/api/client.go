// Package api provides functionality for interacting with the iCloud API.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/rest"
	"golang.org/x/sync/singleflight"
)

const (
	baseEndpoint  = "https://www.icloud.com"
	homeEndpoint  = "https://www.icloud.com"
	setupEndpoint = "https://setup.icloud.com/setup/ws/1"
	authEndpoint  = "https://idmsa.apple.com/appleauth/auth"
	browserUA     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0"
	uaOverrideKey = "X-Rclone-User-Agent"
)

const appleRootCAPEM = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wt
j8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq
6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMa
LOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EB
AMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R
01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEgg
EIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3
cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG
9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW
5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb2
5kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2
F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNp
lMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3
lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6
PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fgxht
bCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7
aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK
1drk/NAJBzewdXUh
-----END CERTIFICATE-----`

type sessionSave func(*Session)

// Client defines the client configuration.
type Client struct {
	appleID             string
	password            string
	srv                 *rest.Client
	Session             *Session
	sessionSaveCallback sessionSave

	pcsMu          sync.Mutex
	pcsReady       map[string]bool
	pcsGroup       singleflight.Group
	webBuildNumber string

	drive *DriveService
}

// New creates a new Client instance.
func New(appleID, password, trustToken string, clientID string, cookies []*http.Cookie, sessionSaveCallback sessionSave) (*Client, error) {
	httpClient := newAppleHTTPClient()

	icloud := &Client{
		appleID:             appleID,
		password:            password,
		srv:                 rest.NewClient(httpClient),
		Session:             NewSession(httpClient),
		sessionSaveCallback: sessionSaveCallback,
	}

	icloud.Session.TrustToken = trustToken
	icloud.Session.Cookies = cookies
	icloud.Session.ClientID = clientID
	return icloud, nil
}

// DriveService returns the DriveService instance associated with the Client.
func (c *Client) DriveService(ctx context.Context) (*DriveService, error) {
	var err error
	if c.drive == nil {
		if err := c.EnsurePCSForServiceOnce(ctx, "iclouddrive"); err != nil {
			return nil, fmt.Errorf("icloud: ADP/PCS consent for iCloud Drive failed: %w", err)
		}
		c.drive, err = NewDriveService(c)
		if err != nil {
			return nil, err
		}
	}
	return c.drive, nil
}

// EnsurePCSForServiceOnce ensures the PCS flow runs at most once concurrently per app.
func (c *Client) EnsurePCSForServiceOnce(ctx context.Context, app string) error {
	c.pcsMu.Lock()
	ready := c.pcsReady != nil && c.pcsReady[app]
	c.pcsMu.Unlock()
	if ready {
		return nil
	}

	_, err, _ := c.pcsGroup.Do(app, func() (any, error) {
		return nil, c.EnsurePCSForService(ctx, app)
	})
	if err != nil {
		return err
	}

	c.pcsMu.Lock()
	if c.pcsReady == nil {
		c.pcsReady = make(map[string]bool)
	}
	c.pcsReady[app] = true
	c.pcsMu.Unlock()
	return nil
}

// Request makes a request and retries it if the session is invalid.
func (c *Client) Request(ctx context.Context, opts rest.Opts, request any, response any) (resp *http.Response, err error) {
	resp, err = c.Session.Request(ctx, opts, request, response)
	if err != nil && resp != nil {
		if resp.StatusCode == 401 || resp.StatusCode == 421 {
			err = c.Authenticate(ctx)
			if err != nil {
				return nil, err
			}

			if c.Session.Requires2FA() {
				return nil, errors.New("re-authentication requires two-factor approval; run rclone config reconnect")
			}
			return c.RequestNoReAuth(ctx, opts, request, response)
		}
	}
	return resp, err
}

// RequestNoReAuth makes a request without re-authenticating.
func (c *Client) RequestNoReAuth(ctx context.Context, opts rest.Opts, request any, response any) (resp *http.Response, err error) {
	return c.Session.Request(ctx, opts, request, response)
}

// Authenticate authenticates the client with the iCloud API.
func (c *Client) Authenticate(ctx context.Context) error {
	if c.Session.Cookies != nil {
		if err := c.Session.ValidateSession(ctx); err == nil {
			fs.Debugf("icloud", "Valid session, no need to reauth")
			return nil
		}
		c.Session.ResetAuthState(false)
	}

	fs.Debugf("icloud", "Authenticating as %s\n", c.appleID)
	if err := c.Session.AuthenticateWithPassword(ctx, c.appleID, c.password); err != nil {
		if c.Session.TrustToken != "" {
			fs.Debugf("icloud", "Retrying authentication without saved trust token")
			c.Session.ResetAuthState(true)
			if err = c.Session.AuthenticateWithPassword(ctx, c.appleID, c.password); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if c.sessionSaveCallback != nil {
		c.sessionSaveCallback(c.Session)
	}
	return nil
}

// SignIn signs in the client using the provided context and credentials.
func (c *Client) SignIn(ctx context.Context) error {
	return c.Session.AuthenticateWithPassword(ctx, c.appleID, c.password)
}

// IntoReader marshals the provided values into a JSON encoded reader.
func IntoReader(values any) (*bytes.Reader, error) {
	m, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(m), nil
}

// RequestError holds info on a result state, icloud can return a 200 but the result is unknown.
type RequestError struct {
	Status string
	Text   string
}

// Error satisfy the error interface.
func (e *RequestError) Error() string {
	return fmt.Sprintf("%s: %s", e.Text, e.Status)
}

func newRequestError(Status string, Text string) *RequestError {
	return &RequestError{
		Status: strings.ToLower(Status),
		Text:   Text,
	}
}

// newRequestErrorf makes a new error from sprintf parameters.
func newRequestErrorf(Status string, Text string, Parameters ...any) *RequestError {
	return newRequestError(strings.ToLower(Status), fmt.Sprintf(Text, Parameters...))
}

func newAppleHTTPClient() *http.Client {
	httpClient := fshttp.NewClient(context.Background())
	if transport, ok := httpClient.Transport.(*fshttp.Transport); ok {
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		rootCAs.AppendCertsFromPEM([]byte(appleRootCAPEM))
		tlsConfig := &tls.Config{RootCAs: rootCAs}
		if transport.TLSClientConfig != nil {
			tlsConfig = transport.TLSClientConfig.Clone()
			tlsConfig.RootCAs = rootCAs
		}
		transport.TLSClientConfig = tlsConfig
		transport.SetRequestFilter(func(req *http.Request) {
			if override := req.Header.Get(uaOverrideKey); override != "" {
				req.Header.Set("User-Agent", override)
				req.Header.Del(uaOverrideKey)
			}
		})
	}
	return httpClient
}
