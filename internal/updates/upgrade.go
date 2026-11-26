package updates

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
)

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// unitName is a systemd unit that runs mohurd: mohurd.service, or another
// instance on the same machine such as mohurd-gamma.service.
var unitName = regexp.MustCompile(`^mohurd(-[a-z0-9-]{1,40})?\.service$`)

// ValidUnit reports whether a unit name is one Upgrade may restart.
func ValidUnit(u string) bool { return unitName.MatchString(u) }

// Upgrader replaces this server's binary with the latest signed release.
type Upgrader struct {
	Checker *Checker
	Running string // this binary's version
	Exe     string // the binary to replace
	Arch    string // its processor, as Go names it

	// Units lists the running mohurd units; Restart restarts one and Active
	// reports whether it is running. The command uses systemctl.
	Units   func() ([]string, error)
	Restart func(unit string) error
	Active  func(unit string) bool
	// Settle is how long to wait after a restart before asking; zero is two
	// seconds.
	Settle time.Duration

	Out io.Writer
}

// ErrUpToDate means there is nothing newer to install.
var ErrUpToDate = errors.New("up to date")

func (u *Upgrader) say(format string, args ...any) {
	if u.Out != nil {
		fmt.Fprintf(u.Out, format+"\n", args...)
	}
}

// Run upgrades: verify the list, verify the file, keep the old binary,
// replace it in one rename, restart, and put the old one back if the new one
// does not stay up.
func (u *Upgrader) Run(ctx context.Context) error {
	u.say("Asking GitHub for the latest signed release list…")
	r, err := u.Checker.Latest(ctx)
	if err != nil {
		return err
	}
	if IsRelease(u.Running) && !Newer(u.Running, r.Version) {
		u.say("This server runs %s, the latest release. Nothing to do.", u.Running)
		return ErrUpToDate
	}
	if !IsRelease(u.Running) {
		u.say("This server runs a development build (%s); installing release %s.", u.Running, r.Version)
	}
	name := BinaryName(r.Version, u.Arch)
	if _, ok := r.Hash(name); !ok {
		return fmt.Errorf("release %s has no build for %s", r.Version, u.Arch)
	}
	u.say("Downloading %s and checking it against the signed list…", name)
	data, err := u.Checker.File(ctx, r, name)
	if err != nil {
		return err
	}
	units, err := u.Units()
	if err != nil {
		return fmt.Errorf("listing mohurd services: %w", err)
	}
	for _, unit := range units {
		if !ValidUnit(unit) {
			return fmt.Errorf("refusing to restart %q", unit)
		}
	}
	previous := u.Exe + ".previous"
	if err := install(u.Exe, previous, data); err != nil {
		return err
	}
	if len(units) == 0 {
		u.say("Installed %s. No mohurd service is running; start it with: systemctl start mohurd", r.Version)
		return nil
	}
	if failed := u.restart(units); failed != "" {
		// Put the old binary back and start it again.
		if err := os.Rename(previous, u.Exe); err != nil {
			return fmt.Errorf("%s did not start, and the previous binary could not be put back (%v); it is at %s", failed, err, previous)
		}
		u.restart(units)
		return fmt.Errorf("%s did not start with %s; the previous version is back. See: journalctl -u %s -n 50", failed, r.Version, failed)
	}
	u.say("Upgraded to %s. The previous binary is kept at %s.", r.Version, previous)
	return nil
}

// restart restarts every unit and returns the first that is not running
// afterwards, or "".
func (u *Upgrader) restart(units []string) string {
	settle := u.Settle
	if settle <= 0 {
		settle = 2 * time.Second
	}
	for _, unit := range units {
		u.say("Restarting %s…", unit)
		if err := u.Restart(unit); err != nil {
			return unit
		}
	}
	time.Sleep(settle)
	for _, unit := range units {
		if !u.Active(unit) {
			return unit
		}
	}
	return ""
}

// install writes data beside exe, keeps the current exe as previous, and
// renames the new file over exe, so exe is always a whole binary.
func install(exe, previous string, data []byte) error {
	info, err := os.Stat(exe)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not the mohurd binary", exe)
	}
	tmp := exe + ".new"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) // #nosec G302 G304 -- a program file beside the one it replaces
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // #nosec G302 -- a program must be executable
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Link(exe, previous); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keeping the previous binary: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
