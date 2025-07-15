package kubelogin

// This is a simplified version of the code from kubelogin. Only standalone mode is needed.
// https://github.com/int128/kubelogin/blob/v1.30.1/pkg/di/wire_gen.go

import (
	"context"
	"fmt"
	"os"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/infrastructure/reader"
	loader2 "github.com/int128/kubelogin/pkg/kubeconfig/loader"
	"github.com/int128/kubelogin/pkg/kubeconfig/writer"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
)

var skipTLSVerify = "false"

type Standalone struct {
	standalone *standalone.Standalone
}

func NewStandalone() *Standalone {
	stdin := os.Stdin
	clock := &clock.Real{}
	loggerInterface := logger.New()
	browserInterface := &browser.Browser{}

	loaderLoader := loader.Loader{}
	factory := &client.Factory{
		Loader: loaderLoader,
		Clock:  clock,
		Logger: loggerInterface,
	}
	authcodeBrowser := &authcode.Browser{
		Browser: browserInterface,
		Logger:  loggerInterface,
	}
	readerReader := &reader.Reader{
		Stdin: stdin,
	}
	keyboard := &authcode.Keyboard{
		Reader: readerReader,
		Logger: loggerInterface,
	}
	ropcROPC := &ropc.ROPC{
		Reader: readerReader,
		Logger: loggerInterface,
	}
	deviceCode := &devicecode.DeviceCode{
		Browser: browserInterface,
		Logger:  loggerInterface,
	}
	authenticationAuthentication := &authentication.Authentication{
		ClientFactory:    factory,
		Logger:           loggerInterface,
		AuthCodeBrowser:  authcodeBrowser,
		AuthCodeKeyboard: keyboard,
		ROPC:             ropcROPC,
		DeviceCode:       deviceCode,
	}
	loader3 := &loader2.Loader{}
	writerWriter := &writer.Writer{}

	return &Standalone{
		standalone: &standalone.Standalone{
			Authentication:   authenticationAuthentication,
			KubeconfigLoader: loader3,
			KubeconfigWriter: writerWriter,
			Logger:           loggerInterface,
			Clock:            clock,
		},
	}
}

const oidcConfigErrorMessage = `No configuration found.
You need to set up kubeconfig files and KUBECONFIG environment variable.
Run:

	kanopy-oidc oidc-login setup

`

func (s *Standalone) Do(ctx context.Context, authenticationOptions *AuthenticationOptions) error {
	in := standaloneInput(authenticationOptions.GrantOptionSet())

	if skipTLSVerify == "true" {
		fmt.Println("Skipping TLS verification")
		in.TLSClientConfig = tlsclientconfig.Config{
			SkipTLSVerify: true,
		}
	}
	_, err := s.standalone.KubeconfigLoader.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)

	if err != nil {
		s.standalone.Logger.Printf(oidcConfigErrorMessage)
		return fmt.Errorf("could not find the current authentication provider: %w", err)
	}

	return s.standalone.Do(ctx, in)
}

func standaloneInput(o authentication.GrantOptionSet) standalone.Input {
	return standalone.Input{
		GrantOptionSet: o,
	}
}
