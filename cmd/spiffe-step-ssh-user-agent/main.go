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
	SpiffeSocket string
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
			{
				ID:           "A",
				SpiffeSocket: getRequiredEnv("SPIFFE_ENDPOINT_SOCKET_A"),
				FetchCAURL:   getRequiredEnv("SPIFFE_STEP_SSH_FETCHCA_URL_A"),
				StepCAURL:    getRequiredEnv("SPIFFE_STEP_SSH_URL_A"),
				Principal:    principal,
			},
			{
				ID:           "B",
				SpiffeSocket: getRequiredEnv("SPIFFE_ENDPOINT_SOCKET_B"),
				FetchCAURL:   getRequiredEnv("SPIFFE_STEP_SSH_FETCHCA_URL_B"),
				StepCAURL:    getRequiredEnv("SPIFFE_STEP_SSH_URL_B"),
				Principal:    principal,
			},
		}
	} else {
		configs = []HAConfig{
			{
				ID:           "Main",
				SpiffeSocket: getRequiredEnv("SPIFFE_ENDPOINT_SOCKET"),
				FetchCAURL:   getRequiredEnv("SPIFFE_STEP_SSH_FETCHCA_URL"),
				StepCAURL:    getRequiredEnv("SPIFFE_STEP_SSH_URL"),
				Principal:    principal,
			},
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	keyring, _ := setupAgentInteraction(ctx, *keyFile == "" && *certFile == "")

	ready := make(chan struct{})
	var once sync.Once

	for _, cfg := range configs {
		go func(c HAConfig) {
			firstRun := true
			for {
				state, spiffeID, err := runWorkflow(ctx, c)
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
		log.Println("Context cancelled before any certificate was obtained.")
		return
	}
	if *keyFile != "" && *certFile != "" {
		fmt.Printf("export SSH_CERT_PATH=%s;\n", *certFile)
		fmt.Printf("export SSH_KEY_PATH=%s;\n", *keyFile)
	}
	if mode == "continuous" {
		fmt.Println("READY")
		<-ctx.Done()
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

func runWorkflow(ctx context.Context, cfg HAConfig) (*ResultState, string, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://" + cfg.SpiffeSocket)))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create x509 source: %w", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get x509 svid: %w", err)
	}
	spiffeID := svid.ID.String()

	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return nil, "", fmt.Errorf("failed to get x509 bundle: %w", err)
	}

	rootPool := x509.NewCertPool()
	for _, root := range bundle.X509Authorities() {
		rootPool.AddCert(root)
	}

	mtlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{svid.Certificates[0].Raw},
			PrivateKey:  svid.PrivateKey,
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
			Certificate: [][]byte{svid.Certificates[0].Raw},
			PrivateKey:  svid.PrivateKey,
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
	token, err := generateX5cToken(svid.Certificates[0], svid.PrivateKey, aud, cfg.Principal)
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
