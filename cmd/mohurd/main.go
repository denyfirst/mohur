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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/server"
	"github.com/denyfirst/mohur/internal/store"
	"github.com/denyfirst/mohur/internal/updates"
)

// version is set by the release build (-X main.version=vX.Y.Z); anything else
// is a development build, which update checks never call behind.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mohurd:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-admin":
			return resetAdmin(os.Args[2:])
		case "upgrade":
			return upgrade(os.Args[2:])
		case "version":
			fmt.Println(version)
			return nil
		}
	}
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
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprint(out, "Usage: mohurd [options]\n       mohurd reset-admin [-instance-key file]\n       mohurd upgrade\n       mohurd version\n\nreset-admin prints a one-time code that lets the admin set a new password\nand authenticator, while the server keeps running.\n\nupgrade installs the latest signed release, as root, after checking its\nsignature and hash, and restarts mohurd; the previous binary is kept.\n\nOptions:\n")
		flag.PrintDefaults()
	}
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
	// Update checks ask GitHub only when an admin presses Check now, or daily
	// once an admin turns that on.
	upd := &updates.Service{Checker: &updates.Checker{}, Settings: st, Running: version}
	srv.SetUpdates(upd)
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
	go upd.Run(ctx)
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()
	log.Info("mohurd listening", "addr", *listen, "version", version)
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

// resetAdmin prints a one-time code that lets the admin set a new password
// and authenticator from the sign-in page. It reads only the instance key, so
// the server keeps running.
func resetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	keyFile := fs.String("instance-key", "/etc/mohur/instance.key", "the instance key file the server uses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("reset-admin takes no arguments")
	}
	code, err := store.ResetCode(*keyFile, time.Now())
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot read %s: run this with sudo", *keyFile)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("no instance key at %s: give the one the server uses with -instance-key", *keyFile)
	case err != nil:
		return err
	}
	fmt.Printf("\nOpen this server's sign-in page, choose \"Forgot your password?\" and enter this code:\n\n    %s\n\nIt works once, within an hour. It lets the admin set a new password and authenticator.\n\n", group(code))
	return nil
}

// upgrade installs the latest signed release over this binary and restarts
// every running mohurd service, putting the old binary back if they do not
// come up.
func upgrade(args []string) error {
	if len(args) != 0 {
		return errors.New("upgrade takes no arguments")
	}
	if runtime.GOOS != "linux" {
		return errors.New("upgrade runs on the Linux server")
	}
	if os.Geteuid() != 0 {
		return errors.New("upgrade replaces the server program: run it with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	u := &updates.Upgrader{
		Checker: &updates.Checker{}, Running: version, Exe: exe, Arch: runtime.GOARCH, Out: os.Stdout,
		Units:   runningUnits,
		Restart: func(unit string) error { return exec.CommandContext(ctx, "systemctl", "restart", unit).Run() }, // #nosec G204 -- unit names are checked by updates.ValidUnit
		Active: func(unit string) bool {
			return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil // #nosec G204 -- as above
		},
	}
	err = u.Run(ctx)
	if errors.Is(err, updates.ErrUpToDate) {
		return nil
	}
	return err
}

// runningUnits lists the active systemd services named mohurd or mohurd-*.
func runningUnits() ([]string, error) {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=active", "--plain", "--no-legend", "--no-pager", "mohurd*.service").Output()
	if err != nil {
		return nil, err
	}
	var units []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) > 0 && updates.ValidUnit(f[0]) {
			units = append(units, f[0])
		}
	}
	return units, nil
}
