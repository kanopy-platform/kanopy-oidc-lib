package dex

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(providerConfig))
}

func providerConfig(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		fmt.Println("returning access token")
		w.Header().Add("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","token_type":"bearer","expiry":"0001-01-01T00:00:00Z"}`))
		if err != nil {
			panic(err)
		}
		return
	}

	out := strings.NewReplacer("{Issuer}", r.Host).Replace(OIDCCONFIG)
	_, err := w.Write([]byte(out))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func TestClientOptions(t *testing.T) {
	defaultScopes := []string{"openid", "profile", "email", "groups"}
	defaultEndpoint := oauth2.Endpoint{
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
	}

	ts := newTestServer()
	defaultIssuer := ts.URL
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // test server certificate is not trusted.
			},
		},
	}
	defaultCtx := oidc.ClientContext(context.Background(), hc)

	tests := map[string]struct {
		expected oauth2.Config
		err      bool
		options  []ClientOption
	}{

		"noClientID": {
			err: true,
		},
		"noAuthURL": {
			err: true,
			expected: oauth2.Config{
				ClientID: "clientID",
				Endpoint: oauth2.Endpoint{
					TokenURL: "https://example.com/token",
				},
			},
		},
		"noTokenURL": {
			err: true,
			expected: oauth2.Config{
				ClientID: "clientID",
				Endpoint: oauth2.Endpoint{
					AuthURL: "https://example.com/auth",
				},
			},
		},
		"required": {
			expected: oauth2.Config{
				ClientID:    "clientID",
				Endpoint:    defaultEndpoint,
				RedirectURL: "http://localhost:8888/",
				Scopes:      defaultScopes,
			},
			options: []ClientOption{
				WithClientID("clientID"),
				WithConfig(oauth2.Config{
					Endpoint: defaultEndpoint,
				})},
		},
		"customport": {
			expected: oauth2.Config{
				ClientID:    "clientID",
				Endpoint:    defaultEndpoint,
				RedirectURL: "http://localhost:1337/",
				Scopes:      defaultScopes,
			},
			options: []ClientOption{
				WithClientID("clientID"),
				WithConfig(oauth2.Config{
					Endpoint: defaultEndpoint,
				}),
				WithCallbackPort("1337")},
		},
		"refresh": {
			expected: oauth2.Config{
				ClientID:    "clientID",
				Endpoint:    defaultEndpoint,
				RedirectURL: "http://localhost:8888/",
				Scopes:      append(defaultScopes, "offline_access"),
			},
			options: []ClientOption{
				WithClientID("clientID"),
				WithConfig(oauth2.Config{
					Endpoint: defaultEndpoint,
				}),
				WithRefresh()},
		},
		"WithSecret": {
			expected: oauth2.Config{
				ClientID:     "clientID",
				ClientSecret: "abcedfg",
				Endpoint:     defaultEndpoint,
				RedirectURL:  "http://localhost:8888/",
				Scopes:       defaultScopes,
			},
			options: []ClientOption{
				WithClientID("clientID"),
				WithConfig(oauth2.Config{
					Endpoint: defaultEndpoint,
				}),
				WithSecret("abcedfg")},
		},
		"issuer": {
			expected: oauth2.Config{
				ClientID: "clientID",
				Endpoint: oauth2.Endpoint{
					AuthURL:       fmt.Sprintf("%s/auth", ts.URL),
					TokenURL:      fmt.Sprintf("%s/token", ts.URL),
					DeviceAuthURL: fmt.Sprintf("%s/device/code", ts.URL),
				},
				RedirectURL: "http://localhost:8888/",
				Scopes:      defaultScopes,
			},
			options: []ClientOption{
				WithClientID("clientID"),
				WithIssuer(defaultIssuer),
				WithContext(defaultCtx),
			},
		},
	}

	for name, tc := range tests {
		c, err := NewClient(tc.options...)
		require.True(t, (err != nil) == tc.err, name)
		if err != nil {
			continue
		}
		require.Equal(t, tc.expected, c.config, name)
	}
}

func TestVerifierIdempotency(t *testing.T) {
	c := &Client{}

	v := c.Verifier()
	assert.NotEmpty(t, v)
	assert.Equal(t, c.Verifier(), v, "should return the same verifier")
}

func TestAuthURLGeneration(t *testing.T) {

	tests := map[string]struct {
		in Client
	}{
		"default": {
			in: Client{
				config: oauth2.Config{
					Endpoint: oauth2.Endpoint{
						AuthURL: "https://example.com/auth",
					},
				},
			},
		},
		"namedConnector": {
			in: Client{
				connector: "testconnector",
				config: oauth2.Config{
					Endpoint: oauth2.Endpoint{
						AuthURL: "https://example.com/auth",
					},
				},
			},
		},
		"client-secret": {
			in: Client{
				secret: "testsecret",
				config: oauth2.Config{
					Endpoint: oauth2.Endpoint{
						AuthURL: "https://example.com/auth",
					},
				},
			},
		},
	}

	for name, tc := range tests {
		authURL, err := url.Parse(tc.in.URL())
		assert.NoError(t, err)
		if err != nil {
			continue
		}

		assert.Equal(t, "example.com", authURL.Hostname(), name)

		params := authURL.Query()
		assert.Equal(t, "code", params.Get("response_type"), name)
		assert.Equal(t, "S256", params.Get("code_challenge_method"), name)
		assert.Equal(t, oauth2.S256ChallengeFromVerifier(tc.in.verifier), params.Get("code_challenge"), name)

		// These are optional parameters that should be empty if not set.
		assert.Equal(t, tc.in.connector, params.Get("connector_id"), name)
		assert.Equal(t, tc.in.secret, params.Get("client_secret"), name)

	}
}

func TestCallbackHandlerRedirectHandler(t *testing.T) {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}
	c, err := NewClient(WithIssuer(""), WithClientID("clientID"), WithConfig(config))
	assert.NoError(t, err)

	code := "scqrqelnaovzxwyiwoeevvfb6"

	tests := map[string]struct {
		req *http.Request
		err bool
	}{
		"empty": {
			err: true,
			req: httptest.NewRequest("GET", "http://localhost:8888/", nil),
		},
		"missingCode": {
			req: httptest.NewRequest("GET", fmt.Sprintf("http://localhost:8888/?state=%s", c.state), nil),
			err: true,
		},
		"missingState": {
			req: httptest.NewRequest("GET", fmt.Sprintf("http://localhost:8888/?code=%s", code), nil),
			err: true,
		},
		"invalidState": {
			req: httptest.NewRequest("GET", fmt.Sprintf("http://localhost:8888/?state=boomboom&code=%s", code), nil),
			err: true,
		},
		"validRequest": {
			req: httptest.NewRequest("GET", fmt.Sprintf("http://localhost:8888/?state=%s&code=%s", c.state, code), nil),
		},
	}

	for name, tc := range tests {
		w := httptest.NewRecorder()
		var e error
		var outcode string
		go c.RedirectHandler(w, tc.req)

		select {
		case outcode = <-c.code:
		case e = <-c.err:
		}

		resp := w.Result()
		if tc.err {
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
			assert.Error(t, e, name)
			continue
		} else {
			assert.Equal(t, http.StatusOK, resp.StatusCode, name)
			assert.NoError(t, e, name)
		}
		assert.Equal(t, code, outcode, name)
	}
}
func TestCallbackHandlerStart(t *testing.T) {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}
	c, e := NewClient(WithIssuer(""), WithClientID("clientID"), WithConfig(config), WithCallbackPort(":55555"))
	assert.NoError(t, e)

	e = c.startCallbackHandler()
	assert.NoError(t, e)
	e = c.startCallbackHandler()
	assert.NoError(t, e)
	e = c.startCallbackHandler()
	assert.NoError(t, e)

	e = c.Close()
	assert.NoError(t, e)
	e = c.startCallbackHandler()
	assert.Error(t, e)

}

func TestCallbackHandlerFlow(t *testing.T) {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}
	c, e := NewClient(WithIssuer(""), WithClientID("clientID"), WithConfig(config))
	assert.NoError(t, e)

	assert.NoError(t, c.startCallbackHandler())
	defer c.Close()
	r, e := c.waitForCallback(10 * time.Millisecond)
	assert.Error(t, e)
	assert.Empty(t, r)
}

func TestCallbackHandlerFlowWithState(t *testing.T) {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}
	c, e := NewClient(WithIssuer(""), WithClientID("clientID"), WithConfig(config))
	assert.NoError(t, e)
	defer c.Close() // nolint: errcheck

	assert.NoError(t, c.startCallbackHandler())

	req, e := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:8888/?state=%s&code=1234", c.state), nil)
	assert.NoError(t, e)
	go func() {
		_, e := http.DefaultClient.Do(req)
		assert.NoError(t, e)
	}()

	r, e := c.waitForCallback(10 * time.Millisecond)
	assert.NoError(t, e)
	assert.Equal(t, "1234", r)
}

func TestCallbackLifcycle(t *testing.T) {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}
	c, e := NewClient(WithIssuer(""), WithClientID("clientID"), WithConfig(config))
	assert.NoError(t, e)

	assert.NoError(t, c.Close())
	assert.NoError(t, c.startCallbackHandler())
	assert.NoError(t, c.Close())
	assert.Equal(t, c.serr, c.startCallbackHandler())
	code, err := c.waitForCallback(10 * time.Millisecond)
	assert.Empty(t, code)
	assert.Equal(t, c.serr, err)
	assert.NoError(t, c.Close())
}

func TestTokenFlow(t *testing.T) {
	c := setupTestClient(t)
	defer c.Close()
	tok, err := c.Token()
	assert.NoError(t, err)
	assert.NotEmpty(t, tok)

	assert.Equal(t, tok, c.token)

	_, err = c.Token()
	assert.NoError(t, err)

}

func TestTokenInMemoryValidFlow(t *testing.T) {
	c := setupTestClient(t)
	defer c.Close()
	tok, err := c.Token()
	assert.NoError(t, err)
	assert.NotEmpty(t, tok)

	assert.Equal(t, tok, c.token)

	_, err = c.Token()
	assert.NoError(t, err)
}

func TestTokenPrefix(t *testing.T) {
	c := setupTestClient(t)
	c.tokenPrefix = "test"
	defer c.Close()
	assert.Contains(t, c.TokenFilePath(), "test-token-clientID.json")
}

func TestTokenInMemoryInValidFlow(t *testing.T) {
	c := setupTestClient(t)
	defer c.Close()
	tok, err := c.Token()
	assert.NoError(t, err)
	assert.NotEmpty(t, tok)
	assert.Equal(t, tok, c.token)

	c.token.RefreshToken = c.token.AccessToken
	c.token.Expiry = time.Now().Add(-1 * time.Hour)

	_, err = c.Token()
	assert.NoError(t, err)
}

func setupTestClient(t *testing.T) *Client {
	config := oauth2.Config{
		ClientID: "clientID",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/token",
		},
	}

	//defaultScopes := []string{"openid", "profile", "email", "groups"}
	ts := newTestServer()
	defaultIssuer := ts.URL
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // test server certificate is not trusted.
			},
		},
	}
	defaultCtx := oidc.ClientContext(context.Background(), hc)

	openBrowserCommand = func(url string) (*exec.Cmd, error) {
		t.Log("openBrowserCommand", url)
		return exec.Command("echo", url), nil
	}

	c, e := NewClient(WithIssuer(defaultIssuer), WithClientID("clientID"), WithConfig(config), WithContext(defaultCtx))
	assert.NoError(t, e)
	t.Log("pushing code to chan")

	go func() {
		c.code <- "1234"
	}()
	return c
}

var OIDCCONFIG string = `{
"issuer": "http://{Issuer}",
  "authorization_endpoint": "http://{Issuer}/auth",
  "token_endpoint": "http://{Issuer}/token",
  "jwks_uri": "http://{Issuer}/keys",
  "userinfo_endpoint": "http://{Issuer}/userinfo",
  "device_authorization_endpoint": "http://{Issuer}/device/code",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "response_types_supported": [
    "code"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "code_challenge_methods_supported": [
    "S256",
    "plain"
  ],
  "scopes_supported": [
    "openid",
    "email",
    "groups",
    "profile",
    "offline_access"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "iat",
    "exp",
    "email",
    "email_verified",
    "locale",
    "name",
    "preferred_username",
    "at_hash"
  ]
}`

func TestFileTokenLoaderSaveToken(t *testing.T) {
	ftl := &FileTokenLoader{}
	tok, err := ftl.LoadToken("testdata/token")
	assert.NoError(t, err)
	assert.NoError(t, ftl.SaveToken("testdata/token", tok))
}

func TestWritePIDToFile(t *testing.T) {
	f, err := openFileErrorIfExists("testdata/pid.lock")
	assert.NoError(t, err)
	assert.NoError(t, writePIDToFile(f))
	p, err := readPIDFromFile("testdata/pid.lock")
	assert.NoError(t, err)
	assert.Equal(t, os.Getpid(), p)
	os.Remove("testdata/pid.lock")
}

func TestFileTokenLoaderLockFile(t *testing.T) {
	ftl := &FileTokenLoader{}
	assert.NoError(t, ftl.lockFile("testdata/lock"))
	assert.Error(t, ftl.lockFile("testdata/lock"))
	os.Remove("testdata/lock.lock") // nolint: errcheck
}

func TestFileTokenLoaderUnlockFile(t *testing.T) {
	ftl := &FileTokenLoader{}
	assert.NoError(t, ftl.lockFile("testdata/unlock"))
	assert.NoError(t, ftl.unlockFile("testdata/unlock"))
}

func TestFileTokenLoaderUnlockFileOnFileNotLocked(t *testing.T) {
	ftl := &FileTokenLoader{}
	assert.NoError(t, ftl.unlockFile("testdata/unlock"))
}

func TestFileTokenLoaderSaveTokenWithoutLock(t *testing.T) {
	ftl := &FileTokenLoader{}
	assert.Error(t, ftl.SaveToken("testdata/token", &oauth2.Token{AccessToken: "test"}))
}

func TestFileTokenLoaderRemoveToken(t *testing.T) {
	ftl := &FileTokenLoader{}
	assert.NoError(t, ftl.lockFile("testdata/token_remove"))
	assert.NoError(t, ftl.SaveToken("testdata/token_remove", &oauth2.Token{AccessToken: "test"}))
	assert.NoError(t, ftl.unlockFile("testdata/token_remove"))

	_, err := ftl.LoadToken("testdata/token_remove")
	assert.NoError(t, err)

	assert.NoError(t, ftl.DeleteToken("testdata/token_remove"))
	assert.Nil(t, ftl.lfile)
}

func TestFileTokenLoaderRemoveToken_FileNotExist(t *testing.T) {
	path := "testdata/token_remove"

	ftl := &FileTokenLoader{}
	assert.NoError(t, ftl.lockFile(path))
	assert.NoError(t, ftl.SaveToken(path, &oauth2.Token{AccessToken: "test"}))
	assert.NoError(t, ftl.unlockFile(path))

	_, err := ftl.LoadToken(path)
	assert.NoError(t, err)

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Remove(ftl.lockName(path)))

	// Ensure that even when file does not exist, DeleteToken does not return an error.
	assert.NoError(t, ftl.DeleteToken(path))
}
