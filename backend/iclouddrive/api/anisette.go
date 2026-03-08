package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/lib/rest"
)

const (
	defaultAnisetteURL     = "http://localhost:6969"
	anisetteClientInfo     = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
	mobileMeClientInfo     = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
	grandslamUserAgent     = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
	trustedDeviceUserAgent = "Xcode"
	mobileMeUserAgent      = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
)

type anisetteProvider struct {
	url string
	srv *rest.Client

	mu      sync.Mutex
	cached  map[string]string
	expires time.Time
}

func newAnisetteProvider(url string, httpClient *http.Client) *anisetteProvider {
	if url == "" {
		url = defaultAnisetteURL
	}
	return &anisetteProvider{
		url: url,
		srv: rest.NewClient(httpClient),
	}
}

// DefaultAnisetteURL returns the default local anisette endpoint.
func DefaultAnisetteURL() string {
	return defaultAnisetteURL
}

func (a *anisetteProvider) headers(ctx context.Context, userID, deviceID string, withClientInfo bool) (map[string]string, error) {
	data, err := a.remoteHeaders(ctx)
	if err != nil {
		return nil, err
	}

	locale := currentLocale()
	headers := map[string]string{
		"X-Apple-I-Client-Time": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-TimeZone":    currentTimezone(),
		"loc":                   locale,
		"X-Apple-Locale":        locale,
		"X-Apple-I-MD":          data["X-Apple-I-MD"],
		"X-Apple-I-MD-LU":       base64.StdEncoding.EncodeToString([]byte(userID)),
		"X-Apple-I-MD-M":        data["X-Apple-I-MD-M"],
		"X-Apple-I-MD-RINFO":    "17106176",
		"X-Mme-Device-Id":       strings.ToUpper(deviceID),
		"X-Apple-I-SRL-NO":      "0",
	}
	if withClientInfo {
		headers["X-Mme-Client-Info"] = anisetteClientInfo
		headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
		headers["X-Xcode-Version"] = "11.2 (11B41)"
	}
	return headers, nil
}

func (a *anisetteProvider) cpd(ctx context.Context, userID, deviceID string) (map[string]any, error) {
	headers, err := a.headers(ctx, userID, deviceID, false)
	if err != nil {
		return nil, err
	}
	cpd := map[string]any{
		"bootstrap": true,
		"icscrec":   true,
		"pbe":       false,
		"prkgen":    true,
		"svct":      "iCloud",
	}
	for k, v := range headers {
		cpd[k] = v
	}
	return cpd, nil
}

func (a *anisetteProvider) remoteHeaders(ctx context.Context) (map[string]string, error) {
	a.mu.Lock()
	if time.Now().Before(a.expires) && a.cached != nil {
		cached := cloneHeaders(a.cached)
		a.mu.Unlock()
		return cached, nil
	}
	a.mu.Unlock()

	var out map[string]string
	_, err := a.srv.CallJSON(ctx, &rest.Opts{
		Method:  "GET",
		RootURL: a.url,
	}, nil, &out)
	if err != nil {
		return nil, fmt.Errorf("anisette request failed: %w", err)
	}
	if out["X-Apple-I-MD"] == "" || out["X-Apple-I-MD-M"] == "" {
		return nil, fmt.Errorf("anisette server %q returned incomplete headers", a.url)
	}

	a.mu.Lock()
	a.cached = cloneHeaders(out)
	a.expires = time.Now().Add(30 * time.Second)
	cached := cloneHeaders(a.cached)
	a.mu.Unlock()
	return cached, nil
}

func cloneHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func currentLocale() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(key); v != "" {
			v = strings.SplitN(v, ".", 2)[0]
			v = strings.SplitN(v, "@", 2)[0]
			if v != "" && v != "C" && v != "POSIX" {
				return v
			}
		}
	}
	return "en_US"
}

func currentTimezone() string {
	name, _ := time.Now().Zone()
	if name == "" {
		return "UTC"
	}
	return name
}
