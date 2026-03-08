package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSessionAddOrReplaceCookie(t *testing.T) {
	session := NewSession(nil)
	session.Cookies = []*http.Cookie{{
		Name:   "foo",
		Value:  "old",
		Domain: "setup.icloud.com",
		Path:   "/",
	}}

	session.AddOrReplaceCookie(&http.Cookie{
		Name:   "foo",
		Value:  "new",
		Domain: "setup.icloud.com",
		Path:   "/",
	})

	if got := len(session.Cookies); got != 1 {
		t.Fatalf("expected 1 cookie, got %d", got)
	}
	if got := session.Cookies[0].Value; got != "new" {
		t.Fatalf("expected replaced cookie value %q, got %q", "new", got)
	}
}

func TestSessionAddOrReplaceCookieReplacesGenericPersistedCookie(t *testing.T) {
	session := NewSession(nil)
	session.Cookies = []*http.Cookie{{
		Name:  "foo",
		Value: "old",
	}}

	session.AddOrReplaceCookie(&http.Cookie{
		Name:   "foo",
		Value:  "new",
		Domain: "setup.icloud.com",
		Path:   "/",
	})

	if got := len(session.Cookies); got != 1 {
		t.Fatalf("expected 1 cookie, got %d", got)
	}
	if got := session.Cookies[0].Value; got != "new" {
		t.Fatalf("expected replaced cookie value %q, got %q", "new", got)
	}
}

func TestCookieHeaderForSetupIncludesWebAuthCookies(t *testing.T) {
	client, err := New("user@example.com", "password", "", "client-id", nil, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client.Session.Cookies = []*http.Cookie{
		{Name: "foo", Value: "bar", Domain: "setup.icloud.com", Path: "/"},
		{Name: "X-APPLE-WEBAUTH-TOKEN", Value: "token", Path: "/"},
		{Name: "X-APPLE-WEBAUTH-USER", Value: "user", Path: "/"},
		{Name: "X-APPLE-WEBAUTH-HSA-LOGIN", Value: "hsa", Path: "/"},
	}

	header := client.CookieHeaderFor(setupWSBase)
	for _, want := range []string{
		"foo=bar",
		"X-APPLE-WEBAUTH-TOKEN=token",
		"X-APPLE-WEBAUTH-USER=user",
		"X-APPLE-WEBAUTH-HSA-LOGIN=hsa",
	} {
		if !strings.Contains(header, want) {
			t.Fatalf("cookie header %q missing %q", header, want)
		}
	}
}

func TestGetCookieStringDedupesCookieNames(t *testing.T) {
	session := NewSession(nil)
	session.Cookies = []*http.Cookie{
		{Name: "foo", Value: "old"},
		{Name: "foo", Value: "new", Domain: "setup.icloud.com", Path: "/"},
		{Name: "bar", Value: "baz"},
	}

	header := session.GetCookieString()
	if strings.Count(header, "foo=") != 1 {
		t.Fatalf("expected exactly one foo cookie in header %q", header)
	}
	if !strings.Contains(header, "foo=new") {
		t.Fatalf("expected latest foo cookie in header %q", header)
	}
}
