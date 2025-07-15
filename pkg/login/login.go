package login

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/cmd"
	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/dex"
	log "github.com/sirupsen/logrus"
)

type config struct {
	issuer      string
	connectorID string
	clientID    string
	secret      string
	port        string
	env         string
	flow        string
	noBrowser   bool
}

const DefaultEnvironment = "prod"

func (c *config) toOptions(ctx context.Context) ([]dex.ClientOption, error) {

	switch {
	case c.issuer == "":
		return nil, fmt.Errorf("missing required issuer")
	case c.connectorID == "":
		return nil, fmt.Errorf("missing required connector ID")
	case c.clientID == "":
		return nil, fmt.Errorf("missing required client ID")
	}

	opts := []dex.ClientOption{
		dex.WithIssuer(c.issuer),
		dex.WithContext(ctx),
		dex.WithConnectorID(c.connectorID),
		dex.WithClientID(c.clientID),
		dex.WithRefresh(),
		dex.WithTokenLoader(&dex.FileTokenLoader{}),
		dex.WithFlow(c.flow),
		dex.WithNoBrowser(c.noBrowser),
	}

	if c.secret != "" {
		opts = append(opts, dex.WithSecret(c.secret))
	}

	if c.port != "" {
		opts = append(opts, dex.WithCallbackPort(c.port))
	}

	if c.env != DefaultEnvironment {
		opts = append(opts, dex.WithTokenPrefix(c.env))
	}

	return opts, nil
}

func newDexClientOptions(ctx context.Context, conf *cmd.Config) ([]dex.ClientOption, error) {
	if conf == nil {
		return nil, fmt.Errorf("missing required configuration")
	}

	clientID := "login"

	if conf.Login.Name != "" {
		clientID = conf.Login.Name
	}

	cfg := config{
		issuer:      fmt.Sprintf("https://%s.%s.%s", conf.Issuer, conf.Environment, conf.Domain),
		connectorID: conf.Login.Connector,
		clientID:    clientID,
		port:        conf.Port,
		env:         conf.Environment,
		flow:        conf.Flow,
		noBrowser:   conf.NoBrowser,
	}

	if conf.Login.Secret != "" {
		cfg.secret = conf.Login.Secret
	}

	return cfg.toOptions(ctx)
}

// login performs the login flow for a user and yields a token.
func Login(ctx context.Context, conf *cmd.Config) (string, error) {
	opts, err := newDexClientOptions(ctx, conf)
	if err != nil {
		return "", fmt.Errorf("failed to login: %w", err)
	}

	client, err := dex.NewClient(opts...)
	if err != nil {
		return "", err
	}
	defer client.Close() // nolint: errcheck

	tok, err := client.Token()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "", nil
		}

		log.Warn("error getting token ", err)

		details, retrieveErr := dex.ErrorToRetrieveError(err)
		if retrieveErr == nil && details.Error == "invalid_request" && strings.Contains(details.ErrorDescription, "Refresh token") {
			// Delete the token file, and retry.
			if deleteErr := client.DeleteToken(); deleteErr != nil {
				return "", fmt.Errorf("%w: %w", err, deleteErr)
			}

			tok, err = client.Token()
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return "", nil
				}
				return "", err
			}
		} else {
			return "", err
		}
	}

	return tok.AccessToken, nil
}
