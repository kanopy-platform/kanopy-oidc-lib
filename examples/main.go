// nolint
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/dex"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	demoURL := "https://dex.example.com"

	// The example below won't work, requires real values
	token, err := dex.NewClientGetToken(
		dex.WithConnectorID("mockcallback"),
		dex.WithIssuer(demoURL),
		dex.WithClientID("mocksecure"),
		dex.WithSecret("hijklmnop"),
		dex.WithContext(ctx),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	if token != nil {
		// There are context cancelled scenarios where the token may be nil.
		fmt.Println(token.AccessToken)
	}
}
