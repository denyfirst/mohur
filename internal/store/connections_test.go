package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/denyfirst/mohur/internal/proto"
)

func TestSetAccessKeepsOnlyRealPeopleWithinTheBound(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, filepath.Join(dir, "instance.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	c, err := s.Asked(proto.OrgDoc{Domain: "beta.e2e.test", Name: "Beta LLC", Server: "mohur.beta.e2e.test", Key: "k"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"murad", "aylin"} {
		if _, _, err := s.Invite(u, u); err != nil {
			t.Fatal(err)
		}
	}
	// No one, until chosen.
	if stored, _ := s.Connection("beta.e2e.test"); c.Allows("aylin") || stored.Allows("aylin") || stored.Allows("murad") {
		t.Fatalf("a new partner allows someone: %+v", c)
	}

	c, err = s.SetAccess("beta.e2e.test", []string{"murad", "aylin", "murad"})
	if err != nil || !slices.Equal(c.People, []string{"aylin", "murad"}) || !c.Allows("aylin") || c.Allows("nigar") {
		t.Fatalf("chosen: %+v, %v", c, err)
	}
	// Past the bound, even with real people, nothing changes.
	many := make([]string, MaxChosen+1)
	for i := range many {
		many[i] = "aylin"
	}
	if _, err := s.SetAccess("beta.e2e.test", many); !errors.Is(err, ErrRefused) {
		t.Fatalf("too many: %v", err)
	}
	if _, err := s.SetAccess("beta.e2e.test", []string{"nobody"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("not a person: %v", err)
	}
	if _, err := s.SetAccess("gamma.e2e.test", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not a partner: %v", err)
	}
	if c, _ := s.Connection("beta.e2e.test"); !slices.Equal(c.People, []string{"aylin", "murad"}) {
		t.Fatalf("a refused change was saved: %+v", c)
	}
	c, err = s.SetAccess("beta.e2e.test", nil)
	if err != nil || len(c.People) != 0 || c.Allows("aylin") {
		t.Fatalf("no one: %+v, %v", c, err)
	}
}

func TestSetPartnersChangesOnePersonOnEveryList(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, filepath.Join(dir, "instance.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, d := range []string{"beta.e2e.test", "gamma.e2e.test", "delta.e2e.test"} {
		if _, err := s.Asked(proto.OrgDoc{Domain: d, Name: d, Server: "mohur." + d, Key: "k"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"murad", "aylin"} {
		if _, _, err := s.Invite(u, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetAccess("delta.e2e.test", []string{"aylin", "murad"}); err != nil {
		t.Fatal(err)
	}
	lists := func() map[string][]string {
		out := map[string][]string{}
		conns, _ := s.Connections()
		for _, c := range conns {
			out[c.Domain] = c.People
		}
		return out
	}

	changed, err := s.SetPartners("murad", []string{"gamma.e2e.test", "beta.e2e.test", "gamma.e2e.test"})
	slices.Sort(changed)
	if err != nil || !slices.Equal(changed, []string{"beta.e2e.test", "delta.e2e.test", "gamma.e2e.test"}) {
		t.Fatalf("changed %v, %v", changed, err)
	}
	got := lists()
	if !slices.Equal(got["beta.e2e.test"], []string{"murad"}) || !slices.Equal(got["gamma.e2e.test"], []string{"murad"}) || !slices.Equal(got["delta.e2e.test"], []string{"aylin"}) {
		t.Fatalf("lists %v", got)
	}
	// The same choice again changes nothing.
	if changed, err := s.SetPartners("murad", []string{"beta.e2e.test", "gamma.e2e.test"}); err != nil || len(changed) != 0 {
		t.Fatalf("again: %v, %v", changed, err)
	}
	// Unknown people and partners change nothing at all.
	if _, err := s.SetPartners("nobody", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown person: %v", err)
	}
	if _, err := s.SetPartners("murad", []string{"beta.e2e.test", "omega.e2e.test"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("unknown partner: %v", err)
	}
	if after := lists(); !slices.Equal(after["beta.e2e.test"], []string{"murad"}) || !slices.Equal(after["gamma.e2e.test"], []string{"murad"}) {
		t.Fatalf("a refused change was saved: %v", after)
	}
	// None: off every list.
	if _, err := s.SetPartners("murad", nil); err != nil {
		t.Fatal(err)
	}
	for d, people := range lists() {
		if slices.Contains(people, "murad") {
			t.Fatalf("murad is still on %s", d)
		}
	}
}
