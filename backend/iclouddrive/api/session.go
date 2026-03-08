package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/rclone/rclone/lib/rest"
)

// Session represents an iCloud session.
type Session struct {
	SessionToken   string         `json:"session_token"`
	Scnt           string         `json:"scnt"`
	SessionID      string         `json:"session_id"`
	AccountCountry string         `json:"account_country"`
	TrustToken     string         `json:"trust_token"`
	ClientID       string         `json:"client_id"`
	Cookies        []*http.Cookie `json:"cookies"`
	AccountInfo    AccountInfo    `json:"account_info"`
	UserID         string         `json:"user_id"`
	DeviceID       string         `json:"device_id"`
	ADSID          string         `json:"adsid"`
	IDMSToken      string         `json:"idms_token"`
	Pending2FA     bool           `json:"pending_2fa"`

	srv      *rest.Client      `json:"-"`
	anisette *anisetteProvider `json:"-"`
}

// Request makes a JSON request.
func (s *Session) Request(ctx context.Context, opts rest.Opts, request any, response any) (*http.Response, error) {
	resp, err := s.srv.CallJSON(ctx, &opts, &request, &response)
	if resp != nil {
		s.captureResponse(resp)
	}
	return resp, err
}

func (s *Session) captureResponse(resp *http.Response) {
	s.CaptureCookies(resp)
	if resp == nil {
		return
	}
	if val := resp.Header.Get("X-Apple-ID-Account-Country"); val != "" {
		s.AccountCountry = val
	}
	if val := resp.Header.Get("X-Apple-ID-Session-Id"); val != "" {
		s.SessionID = val
	}
	if val := resp.Header.Get("X-Apple-Session-Token"); val != "" {
		s.SessionToken = val
	}
	if val := resp.Header.Get("X-Apple-TwoSV-Trust-Token"); val != "" {
		s.TrustToken = val
	}
	if val := resp.Header.Get("scnt"); val != "" {
		s.Scnt = val
	}
}

// CaptureCookies merges response cookies into the session cookie set.
func (s *Session) CaptureCookies(resp *http.Response) {
	if resp == nil {
		return
	}
	for _, ck := range resp.Cookies() {
		s.AddOrReplaceCookie(ck)
	}
}

// SetAnisetteURL updates the anisette provider used for modern Apple login.
func (s *Session) SetAnisetteURL(rawURL string) {
	if s.anisette == nil {
		s.anisette = newAnisetteProvider(rawURL, newAppleHTTPClient())
		return
	}
	if rawURL == "" {
		rawURL = defaultAnisetteURL
	}
	s.anisette.url = rawURL
}

// AnisetteURL returns the current anisette endpoint.
func (s *Session) AnisetteURL() string {
	if s.anisette == nil || s.anisette.url == "" {
		return defaultAnisetteURL
	}
	return s.anisette.url
}

// SetDeviceIDs restores the persisted Apple virtual-device identifiers.
func (s *Session) SetDeviceIDs(userID, deviceID string) {
	if userID != "" {
		s.UserID = userID
	}
	if deviceID != "" {
		s.DeviceID = deviceID
	}
}

// Requires2FA returns true if the session requires 2FA.
func (s *Session) Requires2FA() bool {
	return s.Pending2FA || (s.AccountInfo.DsInfo != nil && s.AccountInfo.DsInfo.HsaVersion == 2 && s.AccountInfo.HsaChallengeRequired)
}

// DSID returns the account DSID from account info or the web-auth user cookie.
func (s *Session) DSID() string {
	if s.AccountInfo.DsInfo != nil && s.AccountInfo.DsInfo.Dsid != "" {
		return s.AccountInfo.DsInfo.Dsid
	}
	if s == nil {
		return ""
	}
	if s.ADSID != "" {
		return s.ADSID
	}
	re := regexp.MustCompile(`(?:^|:)d=([0-9]+)`)
	if m := re.FindStringSubmatch(s.CookieValue("X-APPLE-WEBAUTH-USER")); len(m) == 2 {
		return m[1]
	}
	return ""
}

// CookieValue returns a cookie value by name.
func (s *Session) CookieValue(name string) string {
	for _, ck := range s.Cookies {
		if ck != nil && ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// ResetAuthState clears transient auth/session fields before a fresh sign-in.
func (s *Session) ResetAuthState(clearTrustToken bool) {
	s.Cookies = nil
	s.SessionToken = ""
	s.Scnt = ""
	s.SessionID = ""
	s.AccountCountry = ""
	s.ADSID = ""
	s.IDMSToken = ""
	s.Pending2FA = false
	s.AccountInfo = AccountInfo{}
	if clearTrustToken {
		s.TrustToken = ""
	}
}

// AuthenticateWithPassword performs Apple's iCloud web SRP login flow.
func (s *Session) AuthenticateWithPassword(ctx context.Context, appleID, password string) error {
	if err := s.SignIn(ctx, appleID, password); err != nil {
		return err
	}
	return s.AuthWithToken(ctx)
}

// SignIn performs the SRP-based sign-in flow used by icloud.com.
func (s *Session) SignIn(ctx context.Context, appleID, password string) error {
	if s.UserID == "" {
		s.UserID = uuid.NewString()
	}
	if s.DeviceID == "" {
		s.DeviceID = uuid.NewString()
	}

	srpSession, err := newAppleSRPSession()
	if err != nil {
		return err
	}

	var initResp struct {
		Iteration int    `json:"iteration"`
		Salt      string `json:"salt"`
		Protocol  string `json:"protocol"`
		B         string `json:"b"`
		C         string `json:"c"`
	}
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/signin/init",
		RootURL:      authEndpoint,
		ExtraHeaders: s.GetAuthHeaders(map[string]string{"Accept": "application/json, text/javascript, */*; q=0.01"}),
		IgnoreStatus: true,
	}
	initReq := map[string]any{
		"a":           base64.StdEncoding.EncodeToString(srpSession.ClientEphemeral()),
		"accountName": appleID,
		"protocols":   []string{"s2k", "s2k_fo"},
	}
	resp, err := s.Request(ctx, opts, initReq, &initResp)
	if err != nil {
		return err
	}
	if resp != nil && resp.StatusCode >= 400 {
		return fmt.Errorf("SRP init failed")
	}

	salt, err := base64.StdEncoding.DecodeString(initResp.Salt)
	if err != nil {
		return err
	}
	serverEphemeral, err := base64.StdEncoding.DecodeString(initResp.B)
	if err != nil {
		return err
	}
	derivedPassword, err := encryptPassword(password, salt, initResp.Iteration, initResp.Protocol)
	if err != nil {
		return err
	}
	proofs, err := srpSession.Complete(appleID, salt, derivedPassword, serverEphemeral)
	if err != nil {
		return err
	}

	trustTokens := []string{}
	if s.TrustToken != "" {
		trustTokens = []string{s.TrustToken}
	}
	var completeResp map[string]any
	completeReq := map[string]any{
		"accountName": appleID,
		"c":           initResp.C,
		"m1":          base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"m2":          base64.StdEncoding.EncodeToString(proofs.ServerProof),
		"rememberMe":  true,
		"trustTokens": trustTokens,
	}
	resp, err = s.Request(ctx, rest.Opts{
		Method:       "POST",
		Path:         "/signin/complete",
		RootURL:      authEndpoint,
		ExtraHeaders: s.GetAuthHeaders(map[string]string{"Accept": "application/json, text/javascript, */*; q=0.01"}),
		IgnoreStatus: true,
	}, completeReq, &completeResp)
	if err != nil {
		return err
	}
	if resp != nil && resp.StatusCode >= 400 {
		if resp.StatusCode == 409 && s.SessionToken != "" {
			return nil
		}
		if errors, ok := completeResp["serviceErrors"].([]any); ok && len(errors) > 0 {
			if first, ok := errors[0].(map[string]any); ok {
				if msg, ok := first["message"].(string); ok && msg != "" {
					return fmt.Errorf("SRP password challenge failed: %s", msg)
				}
			}
		}
		if msg, ok := completeResp["errorMessage"].(string); ok && msg != "" {
			return fmt.Errorf("SRP password challenge failed: %s", msg)
		}
		return fmt.Errorf("SRP password challenge failed")
	}
	return nil
}

// AuthWithToken authenticates the session with the setup endpoint.
func (s *Session) AuthWithToken(ctx context.Context) error {
	values := map[string]any{
		"accountCountryCode": s.AccountCountry,
		"dsWebAuthToken":     s.SessionToken,
		"extended_login":     true,
		"trustToken":         s.TrustToken,
	}
	body, err := IntoReader(values)
	if err != nil {
		return err
	}
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/accountLogin",
		ExtraHeaders: s.GetHeaders(map[string]string{}),
		RootURL:      setupEndpoint,
		Body:         body,
	}

	_, err = s.Request(ctx, opts, nil, &s.AccountInfo)
	if err != nil {
		return err
	}
	s.Pending2FA = s.AccountInfo.HsaChallengeRequired
	return nil
}

func (s *Session) gsaRequest(ctx context.Context, parameters map[string]any) (map[string]any, error) {
	cpd, err := s.anisette.cpd(ctx, s.UserID, s.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain anisette headers from %q: %w", s.AnisetteURL(), err)
	}

	body, err := marshalPlist(map[string]any{
		"Header": map[string]any{"Version": "1.0.1"},
		"Request": mergeAny(map[string]any{
			"cpd": cpd,
		}, parameters),
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.srv.Call(ctx, &rest.Opts{
		Method:      "POST",
		RootURL:     "https://gsa.apple.com/grandslam/GsService2",
		ContentType: "text/x-xml-plist",
		Body:        bytes.NewReader(body),
		ExtraHeaders: map[string]string{
			"Accept":            "*/*",
			"X-MMe-Client-Info": anisetteClientInfo,
			uaOverrideKey:       grandslamUserAgent,
		},
	})
	if resp != nil {
		s.captureResponse(resp)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	rootValue, err := unmarshalPlist(raw)
	if err != nil {
		return nil, err
	}
	root, err := plistMap(rootValue)
	if err != nil {
		return nil, err
	}
	return plistMap(root["Response"])
}

func (s *Session) loginMobileMe(ctx context.Context, appleID, idmsPET string) error {
	headers, err := s.anisette.headers(ctx, s.UserID, s.DeviceID, false)
	if err != nil {
		return fmt.Errorf("failed to obtain anisette headers from %q: %w", s.AnisetteURL(), err)
	}
	headers["X-Apple-ADSID"] = s.ADSID
	headers["X-Mme-Client-Info"] = mobileMeClientInfo
	headers[uaOverrideKey] = mobileMeUserAgent

	body, err := marshalPlist(map[string]any{
		"apple-id": appleID,
		"delegates": map[string]any{
			"com.apple.mobileme": map[string]any{},
		},
		"password":  idmsPET,
		"client-id": s.UserID,
	})
	if err != nil {
		return err
	}

	resp, err := s.srv.Call(ctx, &rest.Opts{
		Method:       "POST",
		RootURL:      "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
		ContentType:  "text/x-xml-plist",
		UserName:     appleID,
		Password:     idmsPET,
		Body:         bytes.NewReader(body),
		ExtraHeaders: headers,
	})
	if resp != nil {
		s.captureResponse(resp)
	}
	if err != nil {
		return fmt.Errorf("loginDelegates failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	rootValue, err := unmarshalPlist(raw)
	if err != nil {
		return err
	}
	root, err := plistMap(rootValue)
	if err != nil {
		return err
	}
	if delegates, ok := root["delegates"]; ok {
		delegateMap, err := plistMap(delegates)
		if err == nil {
			if mobileme, ok := delegateMap["com.apple.mobileme"]; ok {
				serviceData, err := plistMap(mobileme)
				if err == nil {
					if status, ok := serviceData["status"]; ok {
						if code, _ := plistInt(status); code != 0 {
							msg, _ := plistString(serviceData["status-message"])
							return fmt.Errorf("com.apple.mobileme login failed with status %d: %s", code, msg)
						}
					}
				}
			}
		}
	}
	if status, ok := root["status"]; ok {
		if code, _ := plistInt(status); code != 0 {
			msg, _ := plistString(root["status-message"])
			return fmt.Errorf("loginDelegates failed with status %d: %s", code, msg)
		}
	}
	return nil
}

// RequestTrustedDevice2FA is handled implicitly by Apple's web flow.
func (s *Session) RequestTrustedDevice2FA(ctx context.Context) error {
	return nil
}

// Validate2FACode validates the trusted-device code.
func (s *Session) Validate2FACode(ctx context.Context, code string) error {
	values := map[string]any{"securityCode": map[string]string{"code": code}}
	body, err := IntoReader(values)
	if err != nil {
		return err
	}

	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	_, err = s.Request(ctx, rest.Opts{
		Method:       "POST",
		Path:         "/verify/trusteddevice/securitycode",
		ExtraHeaders: headers,
		RootURL:      authEndpoint,
		Body:         body,
		NoResponse:   true,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("validate2FACode failed: %w", err)
	}
	if err := s.TrustSession(ctx); err != nil {
		return err
	}
	s.Pending2FA = false
	return nil
}

// TrustSession trusts the session.
func (s *Session) TrustSession(ctx context.Context) error {
	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	_, err := s.Request(ctx, rest.Opts{
		Method:        "GET",
		Path:          "/2sv/trust",
		ExtraHeaders:  headers,
		RootURL:       authEndpoint,
		NoResponse:    true,
		ContentLength: common.Int64(0),
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("trustSession failed: %w", err)
	}
	return s.AuthWithToken(ctx)
}

// PrimeSetupSession performs a lenient setup validation round-trip after 2FA.
// Apple currently returns a non-2xx response shape here, but it still refreshes
// setup cookies and trust-token state needed by later PCS calls.
func (s *Session) PrimeSetupSession(ctx context.Context) error {
	opts := rest.Opts{
		Method:        "POST",
		Path:          "/validate",
		ExtraHeaders:  s.GetHeaders(map[string]string{}),
		RootURL:       setupEndpoint,
		ContentLength: common.Int64(0),
		IgnoreStatus:  true,
	}

	var response struct {
		Success     bool     `json:"success"`
		TrustTokens []string `json:"trustTokens"`
	}
	resp, err := s.Request(ctx, opts, nil, &response)
	if err != nil {
		return fmt.Errorf("primeSetupSession failed: %w", err)
	}
	if len(response.TrustTokens) > 0 {
		s.TrustToken = response.TrustTokens[0]
	}
	if resp != nil && (resp.StatusCode >= 200 && resp.StatusCode <= 299 || resp.StatusCode == 421) {
		return nil
	}
	if resp != nil {
		return fmt.Errorf("primeSetupSession failed: unexpected status %d", resp.StatusCode)
	}
	return fmt.Errorf("primeSetupSession failed: no response")
}

// ValidateSession validates the session.
func (s *Session) ValidateSession(ctx context.Context) error {
	opts := rest.Opts{
		Method:        "POST",
		Path:          "/validate",
		ExtraHeaders:  s.GetHeaders(map[string]string{}),
		RootURL:       setupEndpoint,
		ContentLength: common.Int64(0),
	}
	_, err := s.Request(ctx, opts, nil, &s.AccountInfo)
	if err != nil {
		return fmt.Errorf("validateSession failed: %w", err)
	}
	s.Pending2FA = false
	return nil
}

// GetAuthHeaders returns the authentication headers for the session.
func (s *Session) GetAuthHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		"Accept":                           "application/json",
		"Content-Type":                     "application/json",
		"X-Apple-OAuth-Client-Id":          s.ClientID,
		"X-Apple-OAuth-Client-Type":        "firstPartyAuth",
		"X-Apple-OAuth-Redirect-URI":       "https://www.icloud.com",
		"X-Apple-OAuth-Require-Grant-Code": "true",
		"X-Apple-OAuth-Response-Mode":      "web_message",
		"X-Apple-OAuth-Response-Type":      "code",
		"X-Apple-OAuth-State":              s.ClientID,
		"X-Apple-Widget-Key":               s.ClientID,
		"Origin":                           homeEndpoint,
		"Referer":                          fmt.Sprintf("%s/", homeEndpoint),
		uaOverrideKey:                      browserUA,
	}
	if cookies := s.GetCookieString(); cookies != "" {
		headers["Cookie"] = cookies
	}
	maps.Copy(headers, overwrite)
	return headers
}

// GetHeaders gets the authentication headers required for a request.
func (s *Session) GetHeaders(overwrite map[string]string) map[string]string {
	headers := GetCommonHeaders(map[string]string{})
	headers["Cookie"] = s.GetCookieString()
	maps.Copy(headers, overwrite)
	return headers
}

// GetCookieString returns the cookie header string for the session.
func (s *Session) GetCookieString() string {
	var cookieHeader strings.Builder
	for _, cookie := range dedupeCookiesByName(s.Cookies) {
		if cookie == nil || cookie.Name == "" || cookie.Value == "" {
			continue
		}
		cookieHeader.WriteString(cookie.Name)
		cookieHeader.WriteString("=")
		cookieHeader.WriteString(cookie.Value)
		cookieHeader.WriteString(";")
	}
	return cookieHeader.String()
}

func dedupeCookiesByName(cookies []*http.Cookie) []*http.Cookie {
	seen := make(map[string]int)
	out := make([]*http.Cookie, 0, len(cookies))
	for _, ck := range cookies {
		if ck == nil || ck.Name == "" || ck.Value == "" {
			continue
		}
		if i, ok := seen[ck.Name]; ok {
			out[i] = ck
			continue
		}
		seen[ck.Name] = len(out)
		out = append(out, ck)
	}
	return out
}

// GetCommonHeaders generates common HTTP headers with optional overwrite.
func GetCommonHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       baseEndpoint,
		"Referer":      fmt.Sprintf("%s/", baseEndpoint),
		uaOverrideKey:  browserUA,
	}
	maps.Copy(headers, overwrite)
	return headers
}

// AddOrReplaceCookie adds or replaces a cookie using name/domain/path as identity.
func (s *Session) AddOrReplaceCookie(ck *http.Cookie) {
	if ck == nil || ck.Name == "" {
		return
	}
	for i, existing := range s.Cookies {
		if existing == nil || existing.Name != ck.Name {
			continue
		}
		if existing.Domain == ck.Domain && existing.Path == ck.Path {
			s.Cookies[i] = ck
			return
		}
		if (existing.Domain == "" && existing.Path == "") || (ck.Domain == "" && ck.Path == "") {
			s.Cookies[i] = ck
			return
		}
	}
	s.Cookies = append(s.Cookies, ck)
}

// GetCookiesForDomain filters the provided cookies based on the domain of the given URL.
func GetCookiesForDomain(url *url.URL, cookies []*http.Cookie) ([]*http.Cookie, error) {
	var domainCookies []*http.Cookie
	for _, cookie := range dedupeCookiesByName(cookies) {
		if cookie == nil {
			continue
		}
		if cookie.Domain == "" || strings.HasSuffix(url.Host, cookie.Domain) {
			domainCookies = append(domainCookies, cookie)
		}
	}
	return domainCookies, nil
}

// NewSession creates a new Session instance with default values.
func NewSession(httpClient *http.Client) *Session {
	if httpClient == nil {
		httpClient = newAppleHTTPClient()
	}
	session := &Session{
		UserID:   uuid.NewString(),
		DeviceID: uuid.NewString(),
	}
	session.srv = rest.NewClient(httpClient).SetRoot(baseEndpoint)
	session.anisette = newAnisetteProvider(defaultAnisetteURL, httpClient)
	return session
}

func mergeAny(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// AccountInfo represents an account info.
type AccountInfo struct {
	DsInfo                       *ValidateDataDsInfo    `json:"dsInfo"`
	HasMinimumDeviceForPhotosWeb bool                   `json:"hasMinimumDeviceForPhotosWeb"`
	ICDPEnabled                  bool                   `json:"iCDPEnabled"`
	Webservices                  map[string]*webService `json:"webservices"`
	PcsEnabled                   bool                   `json:"pcsEnabled"`
	TermsUpdateNeeded            bool                   `json:"termsUpdateNeeded"`
	ConfigBag                    struct {
		Urls struct {
			AccountCreateUI     string `json:"accountCreateUI"`
			AccountLoginUI      string `json:"accountLoginUI"`
			AccountLogin        string `json:"accountLogin"`
			AccountRepairUI     string `json:"accountRepairUI"`
			DownloadICloudTerms string `json:"downloadICloudTerms"`
			RepairDone          string `json:"repairDone"`
			AccountAuthorizeUI  string `json:"accountAuthorizeUI"`
			VettingURLForEmail  string `json:"vettingUrlForEmail"`
			AccountCreate       string `json:"accountCreate"`
			GetICloudTerms      string `json:"getICloudTerms"`
			VettingURLForPhone  string `json:"vettingUrlForPhone"`
		} `json:"urls"`
		AccountCreateEnabled bool `json:"accountCreateEnabled"`
	} `json:"configBag"`
	HsaTrustedBrowser            bool     `json:"hsaTrustedBrowser"`
	AppsOrder                    []string `json:"appsOrder"`
	Version                      int      `json:"version"`
	IsExtendedLogin              bool     `json:"isExtendedLogin"`
	PcsServiceIdentitiesIncluded bool     `json:"pcsServiceIdentitiesIncluded"`
	IsRepairNeeded               bool     `json:"isRepairNeeded"`
	HsaChallengeRequired         bool     `json:"hsaChallengeRequired"`
	RequestInfo                  struct {
		Country  string `json:"country"`
		TimeZone string `json:"timeZone"`
		Region   string `json:"region"`
	} `json:"requestInfo"`
	PcsDeleted bool `json:"pcsDeleted"`
	ICloudInfo struct {
		SafariBookmarksHasMigratedToCloudKit bool `json:"SafariBookmarksHasMigratedToCloudKit"`
	} `json:"iCloudInfo"`
	Apps map[string]*ValidateDataApp `json:"apps"`
}

// ValidateDataDsInfo represents validation info.
type ValidateDataDsInfo struct {
	HsaVersion                         int      `json:"hsaVersion"`
	LastName                           string   `json:"lastName"`
	ICDPEnabled                        bool     `json:"iCDPEnabled"`
	TantorMigrated                     bool     `json:"tantorMigrated"`
	Dsid                               string   `json:"dsid"`
	HsaEnabled                         bool     `json:"hsaEnabled"`
	IsHideMyEmailSubscriptionActive    bool     `json:"isHideMyEmailSubscriptionActive"`
	IroncadeMigrated                   bool     `json:"ironcadeMigrated"`
	Locale                             string   `json:"locale"`
	BrZoneConsolidated                 bool     `json:"brZoneConsolidated"`
	ICDRSCapableDeviceList             string   `json:"ICDRSCapableDeviceList"`
	IsManagedAppleID                   bool     `json:"isManagedAppleID"`
	IsCustomDomainsFeatureAvailable    bool     `json:"isCustomDomainsFeatureAvailable"`
	IsHideMyEmailFeatureAvailable      bool     `json:"isHideMyEmailFeatureAvailable"`
	ContinueOnDeviceEligibleDeviceInfo []string `json:"ContinueOnDeviceEligibleDeviceInfo"`
	Gilligvited                        bool     `json:"gilligvited"`
	AppleIDAliases                     []any    `json:"appleIdAliases"`
	UbiquityEOLEnabled                 bool     `json:"ubiquityEOLEnabled"`
	IsPaidDeveloper                    bool     `json:"isPaidDeveloper"`
	CountryCode                        string   `json:"countryCode"`
	NotificationID                     string   `json:"notificationId"`
	PrimaryEmailVerified               bool     `json:"primaryEmailVerified"`
	ADsID                              string   `json:"aDsID"`
	Locked                             bool     `json:"locked"`
	ICDRSCapableDeviceCount            int      `json:"ICDRSCapableDeviceCount"`
	HasICloudQualifyingDevice          bool     `json:"hasICloudQualifyingDevice"`
	PrimaryEmail                       string   `json:"primaryEmail"`
	AppleIDEntries                     []struct {
		IsPrimary bool   `json:"isPrimary"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"appleIdEntries"`
	GilliganEnabled    bool   `json:"gilligan-enabled"`
	IsWebAccessAllowed bool   `json:"isWebAccessAllowed"`
	FullName           string `json:"fullName"`
	MailFlags          struct {
		IsThreadingAvailable           bool `json:"isThreadingAvailable"`
		IsSearchV2Provisioned          bool `json:"isSearchV2Provisioned"`
		SCKMail                        bool `json:"sCKMail"`
		IsMppSupportedInCurrentCountry bool `json:"isMppSupportedInCurrentCountry"`
	} `json:"mailFlags"`
	LanguageCode         string `json:"languageCode"`
	AppleID              string `json:"appleId"`
	HasUnreleasedOS      bool   `json:"hasUnreleasedOS"`
	AnalyticsOptInStatus bool   `json:"analyticsOptInStatus"`
	FirstName            string `json:"firstName"`
	ICloudAppleIDAlias   string `json:"iCloudAppleIdAlias"`
	NotesMigrated        bool   `json:"notesMigrated"`
	BeneficiaryInfo      struct {
		IsBeneficiary bool `json:"isBeneficiary"`
	} `json:"beneficiaryInfo"`
	HasPaymentInfo bool   `json:"hasPaymentInfo"`
	PcsDelet       bool   `json:"pcsDelet"`
	AppleIDAlias   string `json:"appleIdAlias"`
	BrMigrated     bool   `json:"brMigrated"`
	StatusCode     int    `json:"statusCode"`
	FamilyEligible bool   `json:"familyEligible"`
}

// ValidateDataApp represents an app.
type ValidateDataApp struct {
	CanLaunchWithOneFactor bool `json:"canLaunchWithOneFactor"`
	IsQualifiedForBeta     bool `json:"isQualifiedForBeta"`
}

// WebService represents a web service.
type webService struct {
	PcsRequired bool   `json:"pcsRequired"`
	URL         string `json:"url"`
	UploadURL   string `json:"uploadUrl"`
	Status      string `json:"status"`
}
