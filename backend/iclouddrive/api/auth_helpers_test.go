package api

import (
	"bytes"
	"net/http"
	"testing"
)

func TestPlistRoundTrip(t *testing.T) {
	input := map[string]any{
		"Header": map[string]any{"Version": "1.0.1"},
		"Request": map[string]any{
			"cpd": map[string]any{
				"bootstrap": true,
				"svct":      "iCloud",
				"blob":      []byte("hello"),
				"count":     int64(3),
			},
		},
	}

	raw, err := marshalPlist(input)
	if err != nil {
		t.Fatalf("marshalPlist() error = %v", err)
	}
	got, err := unmarshalPlist(raw)
	if err != nil {
		t.Fatalf("unmarshalPlist() error = %v", err)
	}

	root, err := plistMap(got)
	if err != nil {
		t.Fatalf("plistMap(root) error = %v", err)
	}
	req, err := plistMap(root["Request"])
	if err != nil {
		t.Fatalf("plistMap(Request) error = %v", err)
	}
	cpd, err := plistMap(req["cpd"])
	if err != nil {
		t.Fatalf("plistMap(cpd) error = %v", err)
	}
	blob, err := plistBytes(cpd["blob"])
	if err != nil {
		t.Fatalf("plistBytes(blob) error = %v", err)
	}
	if !bytes.Equal(blob, []byte("hello")) {
		t.Fatalf("plist blob = %q, want %q", blob, "hello")
	}
}

func TestPKCS7Unpad(t *testing.T) {
	got, err := pkcs7Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16)
	if err != nil {
		t.Fatalf("pkcs7Unpad() error = %v", err)
	}
	if string(got) != "ICE ICE BABY" {
		t.Fatalf("pkcs7Unpad() = %q", got)
	}
}

func TestGetAuthHeadersIncludesCookies(t *testing.T) {
	session := &Session{
		ClientID: "client-id",
		Cookies: []*http.Cookie{
			{Name: "foo", Value: "bar"},
			{Name: "baz", Value: "qux"},
		},
	}

	headers := session.GetAuthHeaders(nil)
	if got := headers["Cookie"]; got != "foo=bar;baz=qux;" {
		t.Fatalf("Cookie header = %q, want %q", got, "foo=bar;baz=qux;")
	}
}
