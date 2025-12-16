package kubelogin

// This is a simplified version of the code from kubelogin.
// https://github.com/int128/kubelogin/blob/v1.30.1/pkg/cmd/authentication.go

import (
	"time"

	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
)

type AuthenticationOptions struct {
	ListenAddress            []string
	AuthenticationTimeoutSec int
	SkipOpenBrowser          bool
	BrowserCommand           string
}

func (o *AuthenticationOptions) GrantOptionSet() authentication.GrantOptionSet {
	return authentication.GrantOptionSet{
		AuthCodeBrowserOption: &authcode.BrowserOption{
			BindAddress:           o.ListenAddress,
			SkipOpenBrowser:       o.SkipOpenBrowser,
			BrowserCommand:        o.BrowserCommand,
			AuthenticationTimeout: time.Duration(o.AuthenticationTimeoutSec) * time.Second,
			RedirectURLHostname:   "127.0.0.1",
		},
	}
}
