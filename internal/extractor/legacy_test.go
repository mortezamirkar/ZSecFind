package extractor

import (
	"strings"
	"testing"
)

func TestLegacyScannerPatterns(t *testing.T) {
	firebaseKey := "AAAA" + "0123456" + ":" + strings.Repeat("a", 140)
	samples := map[string]string{
		"firebase":     `key = "` + firebaseKey + `"`,
		"google_oauth": `token = "ya29.a0AfH6SMBx-example-token-string"`,
		"facebook":     `token = "EAACEdEose0cBAAB7ZC9ZAZDZD"`,
		"mailgun":      `api_key = "key-1234567890abcdef1234567890abcdef"`,
		"twilio_sid":   `sid = "AC` + strings.Repeat("a", 32) + `"`,
		"s3_url":       `bucket = "s3://my-secret-bucket/config.json"`,
		"basic_auth":   `Authorization: basic YWRtaW46c2VjcmV0`,
	}

	for name, content := range samples {
		r := Extract(content, "test")
		if len(r.Secret) == 0 {
			t.Errorf("expected secret match for legacy %s", name)
		}
	}
}
