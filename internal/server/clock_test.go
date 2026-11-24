package server

import (
	"sync"
	"time"
)

// testClock is a clock a test moves while the servers' own goroutines, such
// as notices to partners, still read it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Set moves the clock to t and returns it.
func (c *testClock) Set(t time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
	return t
}

// Add moves the clock on by d and returns the new time.
func (c *testClock) Add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}
