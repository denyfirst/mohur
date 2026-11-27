package store

import (
	"errors"
	"testing"

	"github.com/denyfirst/mohur/internal/proto"
)

// An app's version is kept with the device that gave it, and only for the
// person's current device.
func TestDeviceAppVersionBelongsToTheCurrentDevice(t *testing.T) {
	s, _, _ := setUpAdmin(t, "a long enough admin password")
	code, _, err := s.Invite("aylin", "Aylin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Invite("murad", "Murad"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Redeem(Join{Code: code, Label: "laptop"}, func(*proto.DeviceCert) {})
	if err != nil || p.Device.App != "" {
		t.Fatalf("joined with %+v, %v", p.Device, err)
	}
	if err := s.SetDeviceApp("aylin", p.Device.ID, "0.1.0"); err != nil {
		t.Fatal(err)
	}
	app := func(user string) string {
		t.Helper()
		p, err := s.Person(user)
		if err != nil || p.Device == nil {
			return ""
		}
		return p.Device.App
	}
	if app("aylin") != "0.1.0" {
		t.Fatalf("stored %q", app("aylin"))
	}
	if err := s.SetDeviceApp("aylin", p.Device.ID, "0.2.0"); err != nil || app("aylin") != "0.2.0" {
		t.Fatalf("update: %v, stored %q", err, app("aylin"))
	}
	for _, c := range []struct {
		user   string
		device uint32
	}{{"aylin", p.Device.ID + 1}, {"murad", 0}, {"murad", 1}, {"nobody", 1}} {
		if err := s.SetDeviceApp(c.user, c.device, "9.9.9"); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s device %d: %v", c.user, c.device, err)
		}
	}
	if app("aylin") != "0.2.0" {
		t.Fatalf("another device changed it: %q", app("aylin"))
	}
	if err := s.ResetDevice("aylin"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceApp("aylin", p.Device.ID, "9.9.9"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a reset device recorded a version: %v", err)
	}
}
