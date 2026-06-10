// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package netguard

import (
	"sync"
	"time"
)

// sweepMinInterval limits how often the lazy cleanup may run.
const sweepMinInterval = time.Minute

// sweepSizeThreshold is the number of tracked keys above which a cleanup is attempted.
const sweepSizeThreshold = 4096

// windowCounter counts events per key within a fixed time window.
// Stale entries are swept lazily while the map grows.
type windowCounter struct {
	mu        sync.Mutex
	window    time.Duration
	entries   map[string]*windowEntry
	lastSweep time.Time
}

type windowEntry struct {
	count       int
	windowStart time.Time
}

func newWindowCounter(window time.Duration) *windowCounter {
	return &windowCounter{
		window:  window,
		entries: make(map[string]*windowEntry),
	}
}

// incr counts one event for the key and returns the number of events in the
// current window and the time left until the window resets.
func (c *windowCounter) incr(key string, now time.Time) (count int, resetIn time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maybeSweep(now)
	e := c.entries[key]
	if e == nil || now.Sub(e.windowStart) >= c.window {
		e = &windowEntry{windowStart: now}
		c.entries[key] = e
	}
	e.count++
	return e.count, e.windowStart.Add(c.window).Sub(now)
}

func (c *windowCounter) maybeSweep(now time.Time) {
	if len(c.entries) < sweepSizeThreshold || now.Sub(c.lastSweep) < sweepMinInterval {
		return
	}
	c.lastSweep = now
	for key, e := range c.entries {
		if now.Sub(e.windowStart) >= c.window {
			delete(c.entries, key)
		}
	}
}

// banList tracks authentication failures per key and bans keys which exceed
// maxFailures within the window.
type banList struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	banDuration time.Duration
	entries     map[string]*banEntry
	lastSweep   time.Time
}

type banEntry struct {
	failures    int
	windowStart time.Time
	bannedUntil time.Time
}

func newBanList(maxFailures int, window, banDuration time.Duration) *banList {
	return &banList{
		maxFailures: maxFailures,
		window:      window,
		banDuration: banDuration,
		entries:     make(map[string]*banEntry),
	}
}

// recordFailure counts one failed attempt and returns the number of failures
// in the current window, and whether this attempt triggered a new ban.
func (b *banList) recordFailure(key string, now time.Time) (count int, newlyBanned bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maybeSweep(now)
	e := b.entries[key]
	if e == nil {
		e = &banEntry{windowStart: now}
		b.entries[key] = e
	} else if now.Sub(e.windowStart) >= b.window {
		e.failures = 0
		e.windowStart = now
	}
	e.failures++
	if e.failures >= b.maxFailures && now.After(e.bannedUntil) {
		e.bannedUntil = now.Add(b.banDuration)
		// restart the failure budget, so that the next failures after the ban
		// expires trigger a new ban only when the budget is exceeded again
		e.failures = 0
		e.windowStart = now
		return b.maxFailures, true
	}
	return e.failures, false
}

// isBanned reports whether the key is banned and for how long.
func (b *banList) isBanned(key string, now time.Time) (banned bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil || !now.Before(e.bannedUntil) {
		return false, 0
	}
	return true, e.bannedUntil.Sub(now)
}

// reset removes every record of the key (failure counter and active ban).
func (b *banList) reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}

func (b *banList) maybeSweep(now time.Time) {
	if len(b.entries) < sweepSizeThreshold || now.Sub(b.lastSweep) < sweepMinInterval {
		return
	}
	b.lastSweep = now
	for key, e := range b.entries {
		if now.Sub(e.windowStart) >= b.window && !now.Before(e.bannedUntil) {
			delete(b.entries, key)
		}
	}
}
