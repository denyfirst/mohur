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
	if _, err := s.Asked(proto.OrgDoc{Domain: "beta.e2e.test", Name: "Beta LLC", Server: "mohur.beta.e2e.test", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"murad", "aylin"} {
		if _, _, err := s.Invite(u, u); err != nil {
			t.Fatal(err)
		}
	}

	c, err := s.SetAccess("beta.e2e.test", true, []string{"murad", "aylin", "murad"})
	if err != nil || !c.Chosen || !slices.Equal(c.People, []string{"aylin", "murad"}) || !c.Allows("aylin") || c.Allows("nigar") {
		t.Fatalf("chosen: %+v, %v", c, err)
	}
	// Past the bound, even with real people, nothing changes.
	many := make([]string, MaxChosen+1)
	for i := range many {
		many[i] = "aylin"
	}
	if _, err := s.SetAccess("beta.e2e.test", true, many); !errors.Is(err, ErrRefused) {
		t.Fatalf("too many: %v", err)
	}
	if _, err := s.SetAccess("beta.e2e.test", true, []string{"nobody"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("not a person: %v", err)
	}
	if _, err := s.SetAccess("gamma.e2e.test", false, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not a partner: %v", err)
	}
	if c, _ := s.Connection("beta.e2e.test"); !slices.Equal(c.People, []string{"aylin", "murad"}) {
		t.Fatalf("a refused change was saved: %+v", c)
	}
	c, err = s.SetAccess("beta.e2e.test", false, []string{"aylin"})
	if err != nil || c.Chosen || c.People != nil || !c.Allows("nigar") {
		t.Fatalf("everyone: %+v, %v", c, err)
	}
}
