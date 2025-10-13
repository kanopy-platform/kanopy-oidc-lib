package dex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kanopy-platform/kanopy-oidc-lib/pkg/cmd"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type Client struct {
	ctx         context.Context
	issuer      string
	port        string
	config      oauth2.Config
	tokenLoader TokenLoader
	token       *oauth2.Token
	flow        string
	noBrowser   bool
	//this long list of fields has a code smell to it
	//this block should probably abstracted into a struct
	//with its own constructor that is an argument to the
	//Client constructor
	tokenPrefix string
	tokenPath   string
	clientID    string
	connector   string
	verifier    string
	state       string
	secret      string
	code        chan string
	err         chan error
	refresh     bool
	server      *http.Server
	serr        error
	lock        *sync.Mutex
}

type ErrorDetails struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func ErrorToRetrieveError(err error) (*ErrorDetails, error) {
	if rerr, ok := err.(*oauth2.RetrieveError); ok {
		ed := &ErrorDetails{}
		if err := json.Unmarshal(rerr.Body, ed); err != nil {
			return nil, err
		}
		return ed, nil
	}
	return nil, fmt.Errorf("error is not a RetrieveError: %w", err)
}

var openBrowserCommand = cmd.GetBrowserCommand

type TokenLoader interface {
	LoadToken(string) (*oauth2.Token, error)
	SaveToken(string, *oauth2.Token) error
	DeleteToken(string) error
}

// DefaultTokenLoader is a function that returns a nil token and nil error.
// if WithTokenLoader is passed as an option, the flow will never load a token
// from state
type DefaultTokenLoader struct{}

func (d *DefaultTokenLoader) LoadToken(path string) (*oauth2.Token, error) {
	return nil, nil
}

func (d *DefaultTokenLoader) SaveToken(path string, tok *oauth2.Token) error {
	return nil
}

func (d *DefaultTokenLoader) DeleteToken(path string) error {
	return nil
}

type FileTokenLoader struct {
	lfile *os.File
}

// FileTokenLoader is a function that loads a token from a file and claims a write lock
func (ftl *FileTokenLoader) LoadToken(path string) (*oauth2.Token, error) {
	if err := ftl.lockFile(path); err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tok := &oauth2.Token{}
	err = json.Unmarshal(bytes, tok)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func (ftl *FileTokenLoader) SaveToken(path string, tok *oauth2.Token) error {
	var merr, werr, ferr error
	var data []byte

	if ftl.lfile == nil {
		ferr = fmt.Errorf("no lock file claimed")
	}

	if ftl.lfile != nil {
		if tok == nil {
			merr = fmt.Errorf("no token to write")
		} else {
			data, merr = json.Marshal(tok)

			if merr == nil {
				werr = os.WriteFile(path, data, 0600)
			}
		}
		ferr = ftl.unlockFile(path)
	}
	return errors.Join(merr, werr, ferr)
}

func (ftl *FileTokenLoader) DeleteToken(path string) error {
	var werr, ferr error

	if ftl.lfile == nil {
		ferr = fmt.Errorf("no lock file claimed")
	}

	if ftl.lfile != nil {
		werr = os.Remove(path)
		if os.IsNotExist(werr) {
			werr = nil
		}

		ferr = ftl.unlockFile(path)
	}

	return errors.Join(werr, ferr)
}

var ErrLockClaimed = fmt.Errorf("lock file claimed by another process")

func (ftl *FileTokenLoader) lockFile(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	f, err := openFileErrorIfExists(ftl.lockName(path))
	if err != nil {
		log.Warnf("failed to get lock, checking for existing lock: %v", err)
		if os.IsExist(err) {
			log.Debug("reading lock file")
			pid, err := readPIDFromFile(ftl.lockName(path))
			if err != nil {
				return fmt.Errorf("failed to read pid from lock file: %v", err)
			}
			return fmt.Errorf("lock claimed by process %d: %w", pid, ErrLockClaimed)
		}
		return fmt.Errorf("failure to obtain lock for unknown reason: %v", err)
	}
	ftl.lfile = f
	return writePIDToFile(f)
}

func (ftl *FileTokenLoader) unlockFile(path string) error {
	log.Debugf("removing lock file %s", ftl.lockName(path))
	err := os.Remove(ftl.lockName(path))
	if os.IsNotExist(err) || err == nil {
		ftl.lfile = nil
		log.Debugf("lock file rm success")
		return nil
	}
	return err
}

func (ftl *FileTokenLoader) lockName(path string) string {
	return path + ".lock"
}

func openFileErrorIfExists(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

func readPIDFromFile(path string) (int, error) {
	// check pid
	bytes, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read lock file: %v", err)
	}

	pids := string(bytes)
	log.Debug("lock file owner pid: ", pids)
	if pids != "" {
		pid, err := strconv.Atoi(pids)
		if err != nil {
			return 0, err
		}

		return pid, nil
	}
	return 0, fmt.Errorf("lock file empty")
}

func writePIDToFile(f *os.File) error {
	if _, err := fmt.Fprintf(f, "%d", os.Getpid()); err != nil {
		return fmt.Errorf("failed to write pid to lock file")
	}
	return f.Close()
}

type ClientOption func(c *Client)

func WithContext(ctx context.Context) ClientOption {
	return func(c *Client) {
		c.ctx = ctx
	}
}
func WithIssuer(URL string) ClientOption {
	return func(c *Client) {
		c.issuer = URL
	}
}
func WithCallbackPort(port string) ClientOption {
	return func(c *Client) {
		c.port = port
	}
}

func WithConnectorID(conID string) ClientOption {
	return func(c *Client) {
		c.connector = conID
	}
}

func WithClientID(clientID string) ClientOption {
	return func(c *Client) {
		c.clientID = clientID
	}
}
func WithSecret(secret string) ClientOption {
	return func(c *Client) {
		c.secret = secret
	}
}

func WithConfig(cfg oauth2.Config) ClientOption {
	return func(c *Client) {
		c.config = cfg
	}
}

func WithRefresh() ClientOption {
	return func(c *Client) {
		c.refresh = true
	}
}

func WithTokenLoader(loader TokenLoader) ClientOption {
	return func(c *Client) {
		c.tokenLoader = loader
	}
}

func WithTokenPrefix(prefix string) ClientOption {
	return func(c *Client) {
		c.tokenPrefix = prefix
	}
}

func WithFlow(flow string) ClientOption {
	return func(c *Client) {
		c.flow = flow
	}
}

func WithNoBrowser(noBrowser bool) ClientOption {
	return func(c *Client) {
		c.noBrowser = noBrowser
	}
}

func NewClient(opts ...ClientOption) (*Client, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	codeChan := make(chan string)
	errChan := make(chan error)

	c := &Client{
		ctx:         context.Background(),
		verifier:    oauth2.GenerateVerifier(),
		state:       oauth2.GenerateVerifier(),
		code:        codeChan,
		err:         errChan,
		lock:        &sync.Mutex{},
		tokenLoader: &DefaultTokenLoader{},
		tokenPath:   home + "/.kanopy/",
		port:        "8888",
		flow:        "auth-code",
	}

	for _, opt := range opts {
		opt(c)
	}

	c.config.Scopes = []string{"openid", "profile", "email", "groups"}
	if c.refresh {
		c.config.Scopes = append(c.config.Scopes, "offline_access")
	}

	c.config.RedirectURL = fmt.Sprintf("http://localhost:%s/", c.port)
	if c.clientID != "" {
		c.config.ClientID = c.clientID
	}

	if c.secret != "" {
		c.config.ClientSecret = c.secret
	}
	if c.issuer != "" {
		provider, err := oidc.NewProvider(c.ctx, c.issuer)
		if err != nil {
			return nil, err
		}

		c.config.Endpoint = provider.Endpoint()
	}

	if c.config.ClientID == "" {
		return nil, fmt.Errorf("ClientID unset but required")
	}

	if c.config.Endpoint.AuthURL == "" || c.config.Endpoint.TokenURL == "" {
		return nil, fmt.Errorf("Oauth endpoint unconfigured: metadataurl or oauth2.Config required")
	}

	return c, nil
}

func (c *Client) TokenFilePath() string {
	prefix := ""
	if c.tokenPrefix != "" {
		prefix = c.tokenPrefix + "-"
	}
	return fmt.Sprintf("%s%stoken-%s%s.json", c.tokenPath, prefix, c.connector, c.clientID)
}

// LoadToken reads a token and claims a write lock
func (c *Client) LoadToken() (*oauth2.Token, error) {
	return c.tokenLoader.LoadToken(c.TokenFilePath())
}

// WriteToken writes the token to the token path and releases the write lock
func (c *Client) WriteToken() error {
	return c.tokenLoader.SaveToken(c.TokenFilePath(), c.token)
}

func (c *Client) DeleteToken() error {
	return c.tokenLoader.DeleteToken(c.TokenFilePath())
}

func (c *Client) Verifier() string {
	if c.verifier == "" {
		c.verifier = oauth2.GenerateVerifier()
	}

	return c.verifier
}

func (c *Client) URL() string {
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(c.verifier),
	}
	if c.connector != "" {
		opts = append(opts, oauth2.SetAuthURLParam("connector_id", c.connector))
	}

	if c.secret != "" {
		opts = append(opts, oauth2.SetAuthURLParam("client_secret", c.secret))
	}

	return c.config.AuthCodeURL(c.state, opts...)
}

func (c *Client) deviceFlow() (*oauth2.Token, error) {
	resp, err := c.config.DeviceAuth(c.ctx, oauth2.S256ChallengeOption(c.verifier))
	if err != nil {
		return nil, err
	}

	if c.noBrowser {
		fmt.Println("navigate to the verification URI to complete device auth flow")
		fmt.Println("code: ", resp.UserCode)
		fmt.Println("uri: ", resp.VerificationURIComplete)
	} else {
		browserCmd, err := openBrowserCommand(resp.VerificationURIComplete)
		if err != nil {
			return nil, err
		}

		err = browserCmd.Start()
		if err != nil {
			return nil, err
		}
	}

	token, err := c.config.DeviceAccessToken(c.ctx, resp, oauth2.VerifierOption(c.verifier))
	if err != nil {
		return nil, err
	}

	if token != nil {
		c.token = token
	}

	return c.token, nil
}

// Token performs the oauth2 flow to get a token from the provider.
// it assumes the clients callback server is already running
func (c *Client) Token() (*oauth2.Token, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// load token from memory
	if c.token != nil {
		if c.token.Valid() {
			return c.token, nil
		}
		if c.token.RefreshToken != "" {
			log.Debugf("refreshing token, inmemory path")
			return c.refreshToken(c.token)
		}
	}

	// load token from token loader
	tok, err := c.LoadToken()
	if tok != nil {
		if tok.Valid() {
			c.token = tok
			return tok, nil
		}

		if tok.RefreshToken != "" {
			log.Debugf("refreshing token, LoadToken path")
			return c.refreshToken(tok)
		}
	}

	// if token loading failed for any reason other than
	// the file not existing, assume we will never
	// successfully write to the path either
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err != nil {
		if errors.Is(err, ErrLockClaimed) {
			return nil, err
		}
		log.Warnf("no existing token to load, starting fresh: %s", err.Error())
	}

	switch c.flow {
	case "device":
		tok, err := c.deviceFlow()
		if err != nil {
			return nil, err
		}
		if tok != nil {
			c.token = tok
		}
	case "auth-code":
		if c.noBrowser {
			return nil, fmt.Errorf("no-browser cannot be specified in auth-code flow")
		}

		tok, err := c.authCodeFlow()
		if err != nil {
			return nil, err
		}
		if tok != nil {
			c.token = tok
		}
	default:
		return nil, fmt.Errorf("invalid flow, received: %q", c.flow)
	}

	return c.token, nil
}

func (c *Client) authCodeFlow() (*oauth2.Token, error) {
	// Start browser flow
	err := c.startCallbackHandler()
	if err != nil {
		return nil, err
	}

	browserCmd, err := openBrowserCommand(c.URL())
	if err != nil {
		return nil, err
	}

	err = browserCmd.Start()
	if err != nil {
		return nil, err
	}

	code, err := c.waitForCallback(120 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for callback: %w", err)
	}

	tok, err := c.config.Exchange(c.ctx, code, oauth2.VerifierOption(c.verifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	if tok != nil {
		c.token = tok
	}

	return c.token, nil
}

func (c *Client) refreshToken(tok *oauth2.Token) (*oauth2.Token, error) {
	ntok, err := c.config.TokenSource(c.ctx, tok).Token()
	if ntok != nil && err == nil {
		c.token = ntok
		return ntok, nil
	}
	return nil, err
}

func (c *Client) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close() // nolint: errcheck

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, e := fmt.Fprintf(w, RESPONSESTRING, fmt.Sprintf("Callback Error: %s.", err.Error()))
		if e != nil {
			err = fmt.Errorf("%s: Error writing response: %s", err.Error(), e.Error())
		}
		c.err <- err
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		var es string
		_, e := fmt.Fprintf(w, RESPONSESTRING, "Callback Error: missing authorization code.")
		if e != nil {
			es = e.Error()
		}
		c.err <- fmt.Errorf("Bad code value: %s", es)
		return
	}
	state := r.FormValue("state")
	if state != c.state {
		w.WriteHeader(http.StatusBadRequest)
		var es string
		_, e := fmt.Fprintf(w, RESPONSESTRING, "Callback Error: state missmatch.")
		if e != nil {
			es = e.Error()
		}
		c.err <- fmt.Errorf("Callback state doesn't match request state: %s", es)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, err = fmt.Fprintf(w, RESPONSESTRING, "Success!")
	if err != nil {
		c.err <- err
	}
	c.code <- code
}

func (c *Client) startCallbackHandler() error {
	//if a server is already running, return
	if c.server != nil {
		if c.serr != nil {
			return c.serr
		}
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%s", c.port)
	//make a new muxer for each call to avoid a panic
	//registrering / multiple times. If a server is already
	//running on the port, listen and server will return
	//an error on the error chan.
	mux := http.NewServeMux()
	c.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func(e chan error) {
		mux.HandleFunc("/", c.RedirectHandler)
		e <- c.server.ListenAndServe()
	}(c.err)

	return nil
}

func (c *Client) waitForCallback(timeout time.Duration) (string, error) {
	if c.server == nil {
		return "", fmt.Errorf("Server not started")
	}

	//if the server is already closed, return the error
	if c.serr != nil {
		return "", c.serr
	}

	d := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(c.ctx, d)
	defer cancel()
	var code string
	var err error
	select {
	case code = <-c.code:
	case err = <-c.err:
	case <-ctx.Done():
		err = ctx.Err()
	}

	return code, err
}

func (c *Client) Close() error {
	log.Debug("starting closing client")
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.WriteToken(); err != nil {
		return fmt.Errorf("failed to write token on cleanup: %w", err)
	}

	if c.server == nil {
		return nil
	}

	if c.serr != nil {
		return nil
	}

	var err error
	serr := c.server.Close()

	// clear chans to keep from blocking
	select {
	case err = <-c.err:
	default:
	}

	select {
	case <-c.code:
	default:
	}

	if c.server == nil {
		return nil
	}
	log.Debug("server closed")
	c.serr = fmt.Errorf("Server closed")
	if err != nil {
		c.serr = err
	}

	return serr
}

const RESPONSESTRING string = `<html><head>
  <title>OIDC Callback Handler</title>
</head>
<body>
    <div>
        <h4>Request Received</h4>
        <p>%s</p>
	<p>This window can be closed.</p>
    </div>
</body></html>`
