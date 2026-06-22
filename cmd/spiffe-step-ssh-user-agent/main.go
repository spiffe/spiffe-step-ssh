package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type HAConfig struct {
	ID           string
	EndpointType string
	SpiffeSocket string
	CredDir      string
	FetchCAURL   string
	StepCAURL    string
	Principal    string
}

type ResultState struct {
	Priv crypto.Signer
	Cert *ssh.Certificate
}

type stepSSHClaims struct {
	CertType   string   `json:"certType"`
	Principals []string `json:"principals,omitempty"`
}

type stepClaims struct {
	SSH *stepSSHClaims `json:"ssh"`
}

type fullClaims struct {
	jwt.Claims
	Step *stepClaims `json:"step"`
}

type Credentials struct {
	Certs     []*x509.Certificate
	Key       crypto.PrivateKey
	TrustPool *x509.CertPool
	SPIFFEID  string
}

type CredentialSource interface {
	GetX509Credentials(ctx context.Context) (*Credentials, error)
}

type unixCredentialSource struct {
	socketPath string
}

func (s *unixCredentialSource) GetX509Credentials(ctx context.Context) (*Credentials, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+s.socketPath)))
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 source: %w", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get x509 svid: %w", err)
	}

	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return nil, fmt.Errorf("failed to get x509 bundle: %w", err)
	}

	rootPool := x509.NewCertPool()
	for _, root := range bundle.X509Authorities() {
		rootPool.AddCert(root)
	}

	return &Credentials{
		Certs:     svid.Certificates,
		Key:       svid.PrivateKey,
		TrustPool: rootPool,
		SPIFFEID:  svid.ID.String(),
	}, nil
}

type fileCredentialSource struct {
	credDir string
}

func (s *fileCredentialSource) GetX509Credentials(ctx context.Context) (*Credentials, error) {
	return loadFileCredentials(s.credDir)
}

func loadFileCredentials(credDir string) (*Credentials, error) {
	credFile := filepath.Join(credDir, "x509", "0", "credential-bundle.pem")
	credData, err := os.ReadFile(credFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential bundle: %w", err)
	}

	certs, privKey, err := parseCredentialBundle(credData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential bundle: %w", err)
	}

	spiffeID := ""
	for _, uri := range certs[0].URIs {
		if uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}
	if spiffeID == "" {
		return nil, fmt.Errorf("no SPIFFE ID in leaf certificate URIs")
	}

	bundleDir := filepath.Dir(credFile)
	matches, err := filepath.Glob(filepath.Join(bundleDir, "*.spiffe-trust-bundle.pem"))
	if err != nil || len(matches) == 0 {
		return nil, fmt.Errorf("no trust bundle file found in %s", bundleDir)
	}
	if len(matches) > 1 {
		log.Fatalf("Found %d trust bundle files in %s; expected exactly 1: %v", len(matches), bundleDir, matches)
	}

	bundleData, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read trust bundle: %w", err)
	}

	trustPool := x509.NewCertPool()
	if !trustPool.AppendCertsFromPEM(bundleData) {
		return nil, fmt.Errorf("failed to parse trust bundle PEM")
	}

	return &Credentials{
		Certs:     certs,
		Key:       privKey,
		TrustPool: trustPool,
		SPIFFEID:  spiffeID,
	}, nil
}

func parseCredentialBundle(data []byte) ([]*x509.Certificate, crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	var certs []*x509.Certificate

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM data found in credential bundle")
	}

	var err error
	privKey, err = parsePrivateKey(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in credential bundle")
	}

	return certs, privKey, nil
}

func parsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type: %s", block.Type)
	}
}

func resolveEndpoint(suffix string) string {
	if v := os.Getenv("SPIFFE_ENDPOINT" + suffix); v != "" {
		return v
	}
	if v := os.Getenv("SPIFFE_ENDPOINT_SOCKET" + suffix); v != "" {
		return "unix://" + v
	}
	return ""
}

func resolveEndpointRequired(suffix string) string {
	if v := resolveEndpoint(suffix); v != "" {
		return v
	}
	log.Fatalf("Required environment variable SPIFFE_ENDPOINT%s or SPIFFE_ENDPOINT_SOCKET%s is not set", suffix, suffix)
	return ""
}

func parseEndpointURL(raw string) (epType, path string) {
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "unix://") {
			return "unix", strings.TrimPrefix(p, "unix://")
		}
		if strings.HasPrefix(p, "file://") {
			return "file", strings.TrimPrefix(p, "file://")
		}
	}
	return "", ""
}

func buildConfig(id, suffix, principal string) HAConfig {
	raw := resolveEndpointRequired(suffix)
	epType, epPath := parseEndpointURL(raw)

	fetchCAVar := "SPIFFE_STEP_SSH_FETCHCA_URL"
	stepCAVar := "SPIFFE_STEP_SSH_URL"
	if suffix != "" {
		fetchCAVar += suffix
		stepCAVar += suffix
	}

	cfg := HAConfig{
		ID:           id,
		EndpointType: epType,
		FetchCAURL:   getRequiredEnv(fetchCAVar),
		StepCAURL:    getRequiredEnv(stepCAVar),
		Principal:    principal,
	}
	switch epType {
	case "unix":
		cfg.SpiffeSocket = epPath
	case "file":
		cfg.CredDir = epPath
	}
	return cfg
}

func generateX5cToken(svidCert *x509.Certificate, svidPriv crypto.Signer, aud string, principal string) (string, error) {
	var alg jose.SignatureAlgorithm
	if _, ok := svidPriv.(*ecdsa.PrivateKey); ok {
		alg = jose.ES256
	} else {
		alg = jose.RS256
	}
	opts := &jose.SignerOptions{}
	opts.WithHeader("x5c", [][]byte{svidCert.Raw})
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: svidPriv}, opts)
	if err != nil {
		return "", err
	}
	now := time.Now()
	cl := fullClaims{
		Claims: jwt.Claims{
			Subject:   principal,
			Issuer:    "x5c@spiffe",
			Audience:  jwt.Audience{aud + "/ssh/sign#x5c/x5c@spiffe"},
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Step: &stepClaims{
			SSH: &stepSSHClaims{
				CertType:   "user",
				Principals: []string{principal},
			},
		},
	}
	return jwt.Signed(sig).Claims(cl).CompactSerialize()
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getRequiredEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return val
}

func main() {
	keyFile := flag.String("key-out", "", "Path to write SSH private key")
	certFile := flag.String("cert-out", "", "Path to write SSH certificate")
	timeout := flag.Duration("timeout", 0, "Timeout for initial startup (e.g., 30s, 1m)")
	flag.Parse()

	mode := getEnv("SPIFFE_STEP_SSH_USER_AGENT_MODE", "one-shot")
	haMode := getEnv("SPIFFE_STEP_SSH_USER_AGENT_HA_MODE", "regular")

	if mode == "continuous" && os.Getenv("DAEMON_STARTED") != "true" {
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), "DAEMON_STARTED=true")

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatalf("Failed to create stdout pipe: %v", err)
		}
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			log.Fatalf("Failed to start daemon: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "READY" {
				break
			}
			fmt.Println(line)
		}
		os.Exit(0)
	}

	principal := "spiffe-step-ssh-user-agent"
	var configs []HAConfig
	if haMode == "ha-agent" {
		configs = []HAConfig{
			buildConfig("A", "_A", principal),
			buildConfig("B", "_B", principal),
		}
	} else {
		configs = []HAConfig{buildConfig("Main", "", principal)}
	}

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx := baseCtx
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(baseCtx, *timeout)
		defer cancel()
	}

	keyring, _ := setupAgentInteraction(ctx, *keyFile == "" && *certFile == "")

	ready := make(chan struct{})
	var once sync.Once

	for _, cfg := range configs {
		cfg := cfg
		var cs CredentialSource
		switch cfg.EndpointType {
		case "file":
			cs = &fileCredentialSource{credDir: cfg.CredDir}
		default:
			cs = &unixCredentialSource{socketPath: cfg.SpiffeSocket}
		}

		go func(c HAConfig) {
			firstRun := true
			for {
				state, spiffeID, err := runWorkflow(ctx, c, cs)
				if err != nil {
					log.Printf("[%s] Workflow failed: %v. Retrying in 10s...", c.ID, err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(10 * time.Second):
						continue
					}
				}

				handleOutput(state, keyring, *keyFile, *certFile, spiffeID)
				if firstRun {
					once.Do(func() {
						close(ready)
					})
					firstRun = false
				}

				if mode == "one-shot" {
					return
				}
				wait := time.Until(time.Unix(int64(state.Cert.ValidBefore), 0))
				select {
				case <-ctx.Done():
					return
				case <-time.After((wait * 2) / 3):
					continue
				}
			}
		}(cfg)
	}

	select {
	case <-ready:
		log.Println("Agent initialized with at least one viable certificate.")
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Fprintf(os.Stderr, "Error: Failed to initialize within the specified timeout of %v\n", *timeout)
			os.Exit(1)
		}
		log.Println("Context cancelled before any certificate was obtained.")
		return
	}

	if *keyFile != "" && *certFile != "" {
		fmt.Printf("export SSH_CERT_PATH=%s;\n", *certFile)
		fmt.Printf("export SSH_KEY_PATH=%s;\n", *keyFile)
	}

	if mode == "continuous" {
		fmt.Println("READY")
		<-baseCtx.Done()
	}
}

func handleOutput(state *ResultState, keyring agent.ExtendedAgent, keyPath, certPath string, spiffeID string) {
	if keyring != nil {
		err := keyring.Add(agent.AddedKey{
			PrivateKey:   state.Priv,
			Certificate:  state.Cert,
			Comment:      spiffeID,
			LifetimeSecs: uint32(time.Until(time.Unix(int64(state.Cert.ValidBefore), 0)).Seconds()),
		})
		if err == nil {
			log.Println("Key and Cert added to SSH Agent.")
			return
		}
	}

	if keyPath != "" && certPath != "" {
		pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(state.Priv)
		pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}
		_ = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
		_ = os.WriteFile(certPath, ssh.MarshalAuthorizedKey(state.Cert), 0644)
		log.Printf("Identity saved to disk: %s", keyPath)
	}
}

func runWorkflow(ctx context.Context, cfg HAConfig, cs CredentialSource) (*ResultState, string, error) {
	creds, err := cs.GetX509Credentials(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get credentials: %w", err)
	}

	spiffeID := creds.SPIFFEID
	rootPool := creds.TrustPool

	mtlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{creds.Certs[0].Raw},
			PrivateKey:  creds.Key,
		}},
		RootCAs: rootPool,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: mtlsConfig},
		Timeout:   10 * time.Second,
	}

	respFetch, err := httpClient.Get(cfg.FetchCAURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch Step CA roots from %s: %w", cfg.FetchCAURL, err)
	}
	defer respFetch.Body.Close()

	pemRoots, err := io.ReadAll(respFetch.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read Step CA roots body: %w", err)
	}

	stepRootPool := x509.NewCertPool()
	if ok := stepRootPool.AppendCertsFromPEM(pemRoots); !ok {
		return nil, "", fmt.Errorf("failed to parse Step CA roots from fetched document")
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public())

	stepTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{creds.Certs[0].Raw},
			PrivateKey:  creds.Key,
		}},
		RootCAs: stepRootPool,
	}

	client, err := ca.NewClient(cfg.StepCAURL,
		ca.WithTransport(&http.Transport{TLSClientConfig: stepTLSConfig}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create step ca client: %w", err)
	}

	aud := cfg.StepCAURL
	signer, ok := creds.Key.(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("private key does not implement crypto.Signer")
	}
	token, err := generateX5cToken(creds.Certs[0], signer, aud, cfg.Principal)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create x5c token: %w", err)
	}

	req := &api.SSHSignRequest{
		PublicKey: pub.Marshal(),
		CertType:  "user",
		OTT:       token,
	}
	if cfg.Principal != "" {
		req.Principals = []string{cfg.Principal}
	}

	resp, err := client.SSHSign(req)
	if err != nil {
		return nil, "", fmt.Errorf("ssh sign request failed: %w", err)
	}

	return &ResultState{Priv: priv, Cert: resp.Certificate.Certificate}, spiffeID, nil
}
