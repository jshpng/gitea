// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package netguard

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseRemoteIP(t *testing.T) {
	assert.Equal(t, net.ParseIP("192.0.2.1"), ParseRemoteIP("192.0.2.1:8080"))
	assert.Equal(t, net.ParseIP("192.0.2.1"), ParseRemoteIP("192.0.2.1"))
	assert.Equal(t, net.ParseIP("2001:db8::1"), ParseRemoteIP("[2001:db8::1]:8080"))
	assert.Equal(t, net.ParseIP("2001:db8::1"), ParseRemoteIP("2001:db8::1"))
	assert.Nil(t, ParseRemoteIP("@"))
	assert.Nil(t, ParseRemoteIP(""))
}

func TestGuardActive(t *testing.T) {
	assert.False(t, NewGuard(Config{}).Active())
	assert.True(t, NewGuard(Config{AllowedNetworks: "10.0.0.0/8"}).Active())
	assert.True(t, NewGuard(Config{BlockedNetworks: "192.0.2.0/24"}).Active())
	assert.True(t, NewGuard(Config{RateLimitEnabled: true, RateLimitRequests: 10, RateLimitWindow: time.Minute}).Active())
	assert.True(t, NewGuard(Config{AuthAutoBanEnabled: true, AuthBanMaxFailures: 5, AuthBanWindow: time.Minute, AuthBanDuration: time.Minute}).Active())

	// incomplete feature configs keep the feature disabled
	assert.False(t, NewGuard(Config{RateLimitEnabled: true}).Active())
	assert.False(t, NewGuard(Config{AuthAutoBanEnabled: true}).Active())
}

func TestGuardIPAllowed(t *testing.T) {
	t.Run("no lists allows everything", func(t *testing.T) {
		g := NewGuard(Config{})
		assert.True(t, g.IPAllowed(net.ParseIP("192.0.2.1")))
	})

	t.Run("allowlist", func(t *testing.T) {
		g := NewGuard(Config{AllowedNetworks: "10.0.0.0/8, 192.168.0.0/16"})
		assert.True(t, g.IPAllowed(net.ParseIP("10.1.2.3")))
		assert.True(t, g.IPAllowed(net.ParseIP("192.168.1.1")))
		assert.False(t, g.IPAllowed(net.ParseIP("203.0.113.7")))
		// loopback always bypasses the filter
		assert.True(t, g.IPAllowed(net.ParseIP("127.0.0.1")))
		assert.True(t, g.IPAllowed(net.ParseIP("::1")))
		// non-IP peers (e.g. unix sockets) bypass the filter
		assert.True(t, g.IPAllowed(nil))
	})

	t.Run("blocklist", func(t *testing.T) {
		g := NewGuard(Config{BlockedNetworks: "203.0.113.0/24"})
		assert.False(t, g.IPAllowed(net.ParseIP("203.0.113.7")))
		assert.True(t, g.IPAllowed(net.ParseIP("198.51.100.1")))
	})

	t.Run("blocklist wins over allowlist", func(t *testing.T) {
		g := NewGuard(Config{AllowedNetworks: "203.0.113.0/24", BlockedNetworks: "203.0.113.7/32"})
		assert.True(t, g.IPAllowed(net.ParseIP("203.0.113.8")))
		assert.False(t, g.IPAllowed(net.ParseIP("203.0.113.7")))
	})

	t.Run("builtin names", func(t *testing.T) {
		g := NewGuard(Config{AllowedNetworks: "private"})
		assert.True(t, g.IPAllowed(net.ParseIP("10.1.2.3")))
		assert.False(t, g.IPAllowed(net.ParseIP("8.8.8.8")))
	})
}

func TestGuardRateLimit(t *testing.T) {
	g := NewGuard(Config{RateLimitEnabled: true, RateLimitRequests: 3, RateLimitWindow: time.Hour})
	ip := net.ParseIP("192.0.2.1")
	for range 3 {
		ok, _ := g.AllowRequest(ip)
		assert.True(t, ok)
	}
	ok, retryAfter := g.AllowRequest(ip)
	assert.False(t, ok)
	assert.Positive(t, retryAfter)

	// other IPs are not affected
	ok, _ = g.AllowRequest(net.ParseIP("192.0.2.2"))
	assert.True(t, ok)

	// loopback is never limited
	for range 10 {
		ok, _ = g.AllowRequest(net.ParseIP("127.0.0.1"))
		assert.True(t, ok)
	}
}

func TestWindowCounterReset(t *testing.T) {
	c := newWindowCounter(time.Minute)
	now := time.Now()
	count, _ := c.incr("k", now)
	assert.Equal(t, 1, count)
	count, _ = c.incr("k", now.Add(30*time.Second))
	assert.Equal(t, 2, count)
	// window expired: counter starts over
	count, _ = c.incr("k", now.Add(61*time.Second))
	assert.Equal(t, 1, count)
}

func TestGuardAuthAutoBan(t *testing.T) {
	g := NewGuard(Config{AuthAutoBanEnabled: true, AuthBanMaxFailures: 3, AuthBanWindow: time.Hour, AuthBanDuration: time.Hour})
	ip := net.ParseIP("192.0.2.1")

	banned, _ := g.IsBanned(ip)
	assert.False(t, banned)

	g.RecordAuthFailure("192.0.2.1:1000")
	g.RecordAuthFailure("192.0.2.1:1001")
	banned, _ = g.IsBanned(ip)
	assert.False(t, banned)

	g.RecordAuthFailure("192.0.2.1:1002")
	banned, retryAfter := g.IsBanned(ip)
	assert.True(t, banned)
	assert.Positive(t, retryAfter)

	// other IPs are not affected
	banned, _ = g.IsBanned(net.ParseIP("192.0.2.2"))
	assert.False(t, banned)

	// reset clears the ban
	g.ResetAuthFailures("192.0.2.1:1003")
	banned, _ = g.IsBanned(ip)
	assert.False(t, banned)

	// loopback is never banned
	for range 10 {
		g.RecordAuthFailure("127.0.0.1:1000")
	}
	banned, _ = g.IsBanned(net.ParseIP("127.0.0.1"))
	assert.False(t, banned)
}

func TestBanListWindowExpiry(t *testing.T) {
	b := newBanList(3, time.Minute, time.Hour)
	now := time.Now()

	// failures spread over more than the window never trigger a ban
	for i := range 4 {
		_, newlyBanned := b.recordFailure("k", now.Add(time.Duration(i)*2*time.Minute))
		assert.False(t, newlyBanned)
	}

	// dense failures trigger the ban exactly at the threshold
	base := now.Add(time.Hour)
	_, newlyBanned := b.recordFailure("j", base)
	assert.False(t, newlyBanned)
	_, newlyBanned = b.recordFailure("j", base.Add(time.Second))
	assert.False(t, newlyBanned)
	count, newlyBanned := b.recordFailure("j", base.Add(2*time.Second))
	assert.True(t, newlyBanned)
	assert.Equal(t, 3, count)

	banned, retryAfter := b.isBanned("j", base.Add(3*time.Second))
	assert.True(t, banned)
	assert.Equal(t, time.Hour-time.Second, retryAfter)

	// ban expires
	banned, _ = b.isBanned("j", base.Add(2*time.Hour))
	assert.False(t, banned)
}

func TestDefaultGuardNoop(t *testing.T) {
	// calling the package level helpers without Init must not panic
	defaultGuard.Store(nil)
	RecordAuthFailure("192.0.2.1:1000")
	ResetAuthFailures("192.0.2.1:1000")

	g := Init(Config{AuthAutoBanEnabled: true, AuthBanMaxFailures: 1, AuthBanWindow: time.Minute, AuthBanDuration: time.Minute})
	RecordAuthFailure("192.0.2.9:1000")
	banned, _ := g.IsBanned(net.ParseIP("192.0.2.9"))
	assert.True(t, banned)
	defaultGuard.Store(nil)
}
