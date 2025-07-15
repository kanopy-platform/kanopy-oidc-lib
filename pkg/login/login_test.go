package login

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigToOptions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg     config
		err     bool
		opcount int
	}{
		"default-valid": {
			cfg: config{
				issuer:      "https://issuer.example.com",
				connectorID: "connector",
				clientID:    "client",
			},
			opcount: 9,
		},
		"missing-issuer": {
			cfg: config{
				connectorID: "connector",
				clientID:    "client",
			},
			err: true,
		},
		"missing-connector": {
			cfg: config{
				issuer:   "issuer",
				clientID: "client",
			},
			err: true,
		},
		"missing-client": {
			cfg: config{
				issuer:      "issuer",
				connectorID: "connector",
			},
			err: true,
		},
		"with-secret": {
			cfg: config{
				issuer:      "issuer",
				connectorID: "connector",
				clientID:    "client",
				secret:      "secret",
			},
			opcount: 10,
		},
		"with-port": {
			cfg: config{
				issuer:      "issuer",
				connectorID: "connector",
				clientID:    "client",
				port:        "55555",
			},
			opcount: 10,
		},
		"with-secret-and-port": {
			cfg: config{
				issuer:      "issuer",
				connectorID: "connector",
				clientID:    "client",
				secret:      "secret",
				port:        "55555",
			},
			opcount: 11,
		},
		"with-env": {
			cfg: config{
				issuer:      "issuer",
				connectorID: "connector",
				clientID:    "client",
				env:         "test",
			},
			opcount: 9,
		},
	}

	for name, test := range tests {
		ctx := context.Background()
		opts, err := test.cfg.toOptions(ctx)
		assert.Equal(t, err != nil, test.err, name)
		assert.Equal(t, test.opcount, len(opts), name)
	}

}
