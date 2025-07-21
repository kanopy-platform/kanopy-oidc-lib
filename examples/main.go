// nolint
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/dex"
)

func main() {
	kindDemoURL := "https://dex.example.com"

	// this is for demonstration purposes only right now
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // test server certificate is not trusted.
			},
		},
	}
	ctx := oidc.ClientContext(context.Background(), hc)

	client, err := dex.NewClient(dex.WithConnectorID("mockcallback"), dex.WithIssuer(kindDemoURL), dex.WithClientID("mocksecure"), dex.WithSecret("hijklmnop"), dex.WithContext(ctx))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	tok, err := client.Token()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(tok)
}
