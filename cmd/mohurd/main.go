// Command mohurd runs one organization's Mohur server: its admin pages, the
// API the desktop app uses, and the federation API partner servers call.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/server"
	"github.com/denyfirst/mohur/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mohurd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir      = flag.String("data", "/var/lib/mohur", "directory for the database and encrypted files")
		keyFile      = flag.String("instance-key", "/etc/mohur/instance.key", "file holding the 32-byte instance key; created if missing")
		listen       = flag.String("listen", ":443", "HTTPS listen address")
		certFile     = flag.String("cert", "/etc/mohur/tls/fullchain.pem", "TLS certificate chain (PEM); re-read when it changes")
		certKeyFile  = flag.String("cert-key", "/etc/mohur/tls/privkey.pem", "TLS private key (PEM)")
		resolver     = flag.String("resolver", "", "DNS server host:port for partner lookups; empty uses the system resolver")
		extraCA      = flag.String("extra-ca", "", "PEM file of extra certificate authorities to trust for partner servers")
		allowPrivate = flag.Bool("allow-private-partners", false, "allow partner servers on private or loopback addresses")
	)
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := store.Open(*dataDir, *keyFile)
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := discover.Config{Resolver: *resolver, AllowPrivate: *allowPrivate}
	if *extraCA != "" {
		pem, err := os.ReadFile(*extraCA)
		if err != nil {
			return err
		}
		if cfg.ExtraRoots, err = discover.ParseRoots(pem); err != nil {
			return fmt.Errorf("%s: %w", *extraCA, err)
		}
	}
	disc, err := discover.New(cfg)
	if err != nil {
		return err
	}

	if !st.HasAdmin() {
		code, err := st.NewSetupCode()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nMohur is not set up yet. Open this server in a browser and enter the setup code:\n\n    %s\n\nIt works for 24 hours and once only.\n\n", group(code))
	}

	certs := &certReloader{certFile: *certFile, keyFile: *certKeyFile}
	if _, err := certs.get(); err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	srv := server.New(st, disc, log)
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certs.get() }},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Run(ctx)
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()
	log.Info("mohurd listening", "addr", *listen)
	if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func group(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		parts = append(parts, code[i:min(i+4, len(code))])
	}
	return strings.Join(parts, "-")
}

// certReloader reads the certificate again when its file changes, so a
// renewed certificate (from Rootwell, certbot or anything else) is used
// without a restart.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	modTime           time.Time
	checked           time.Time
}

func (c *certReloader) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && time.Since(c.checked) < time.Minute {
		return c.cert, nil
	}
	c.checked = time.Now()
	info, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && info.ModTime().Equal(c.modTime) {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.modTime = &cert, info.ModTime()
	return c.cert, nil
}
