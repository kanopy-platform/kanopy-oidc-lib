// nolint
package main

import (
	"fmt"

	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/dex"
)

func main() {

	demoURL := "https://dex.example.com"

	client, err := dex.NewClient(dex.WithConnectorID("mockcallback"), dex.WithIssuer(demoURL), dex.WithClientID("mocksecure"), dex.WithSecret("hijklmnop"))
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
