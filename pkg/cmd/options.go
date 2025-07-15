package cmd

import (
	"fmt"
	"os"

	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/kubelogin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Settings struct {
	WriteConfig bool   `json:"writeConfig,omitempty"`
	ConfigFile  string `json:"configFile,omitempty"`
}

type Config struct {
	File        string             `json:"file,omitempty"`
	Flow        string             `json:"flow,omitempty"`
	NoBrowser   bool               `json:"noBrowser,omitempty"`
	Environment string             `json:"environment,omitempty"`
	Issuer      string             `json:"issuer,omitempty"`
	Domain      string             `json:"domain,omitempty"`
	Clients     map[string]Client  `json:"clients,omitempty"`
	Login       Client             `json:"login,omitempty"`
	Kubectl     Client             `json:"kubectl,omitempty"`
	Port        string             `json:"port,omitempty"`
	Settings    Settings           `json:"settings,omitempty"`
	LogLevel    string             `json:"logLevel,omitempty"`
	Clusters    map[string]Cluster `json:"clusters,omitempty"`
}

type Cluster struct {
	Connector string `json:"connector,omitempty"`
	APIURL    string `json:"apiUrl,omitempty"`
	Scopes    string `json:"scopes,omitempty"`
	Secret    string `json:"secret,omitempty"`
}

type Client struct {
	Connector string `json:"connector,omitempty"`
	Name      string `json:"name,omitempty"`
	Secret    string `json:"secret,omitempty"`
}

func (c *Config) ParseConfig(cmd *cobra.Command, args []string) error {
	viper.SetConfigName("config")
	home, err := os.UserHomeDir()
	if err != nil && c.File == "" {
		return err
	}
	viper.AddConfigPath(fmt.Sprintf("%s/.kanopy", home))

	if c.File != "" {
		viper.SetConfigFile(c.File)
	}

	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	logLevel, err := log.ParseLevel(c.LogLevel)
	if err != nil {
		return err
	}

	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetLevel(logLevel)

	if err = kubelogin.SetKlogV(int32(logLevel) - int32(log.InfoLevel)); err != nil {
		return err
	}

	return viper.Unmarshal(c)
}

func NewConfig() *Config {
	return &Config{
		Clients:  map[string]Client{},
		Clusters: map[string]Cluster{},
	}
}
