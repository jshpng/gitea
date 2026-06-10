// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package netguard provides network-level protection for Gitea instances that
// are exposed to untrusted networks: client IP allow/block lists, per-IP
// request rate limiting and automatic temporary banning of IPs that repeatedly
// fail authentication.
//
// Loopback addresses always bypass every check, because internal components
// (SSH passthrough, internal API calls, health checks from the local host)
// rely on loopback connectivity.
package netguard

import (
	"net"
	"strings"
	"sync/atomic"
	"time"

	"gitea.dev/modules/hostmatcher"
	"gitea.dev/modules/log"
)

// Config contains all the tunables of a Guard, normally loaded from the
// "[security.network]" section of app.ini.
type Config struct {
	// AllowedNetworks is a comma separated list of CIDRs (or the builtins
	// "loopback", "private", "external"). When non-empty, only matching client
	// IPs may access the instance.
	AllowedNetworks string
	// BlockedNetworks is a comma separated list of CIDRs (or builtins) which
	// are always denied. It takes precedence over AllowedNetworks.
	BlockedNetworks string

	// RateLimitEnabled enables the per-IP request rate limiter.
	RateLimitEnabled bool
	// RateLimitRequests is the maximum number of requests a single IP may make
	// within RateLimitWindow.
	RateLimitRequests int
	// RateLimitWindow is the measurement window of the rate limiter.
	RateLimitWindow time.Duration

	// AuthAutoBanEnabled enables automatic temporary banning of client IPs
	// which repeatedly fail authentication.
	AuthAutoBanEnabled bool
	// AuthBanMaxFailures is the number of failed authentication attempts
	// within AuthBanWindow which triggers a ban.
	AuthBanMaxFailures int
	// AuthBanWindow is the measurement window for failed authentication attempts.
	AuthBanWindow time.Duration
	// AuthBanDuration is how long a triggered ban lasts.
	AuthBanDuration time.Duration
}

// Guard combines the IP filter, the rate limiter and the auth-failure ban list.
type Guard struct {
	cfg      Config
	allowed  *hostmatcher.HostMatchList
	blocked  *hostmatcher.HostMatchList
	requests *windowCounter
	failures *banList
}

// NewGuard creates a Guard from the given config. Disabled or incomplete
// features are turned off individually.
func NewGuard(cfg Config) *Guard {
	g := &Guard{cfg: cfg}
	if strings.TrimSpace(cfg.AllowedNetworks) != "" {
		g.allowed = hostmatcher.ParseHostMatchList("security.network.ALLOWED_NETWORKS", cfg.AllowedNetworks)
	}
	if strings.TrimSpace(cfg.BlockedNetworks) != "" {
		g.blocked = hostmatcher.ParseHostMatchList("security.network.BLOCKED_NETWORKS", cfg.BlockedNetworks)
	}
	if cfg.RateLimitEnabled && cfg.RateLimitRequests > 0 && cfg.RateLimitWindow > 0 {
		g.requests = newWindowCounter(cfg.RateLimitWindow)
	}
	if cfg.AuthAutoBanEnabled && cfg.AuthBanMaxFailures > 0 && cfg.AuthBanWindow > 0 && cfg.AuthBanDuration > 0 {
		g.failures = newBanList(cfg.AuthBanMaxFailures, cfg.AuthBanWindow, cfg.AuthBanDuration)
	}
	return g
}

// Active reports whether any protection feature is enabled.
func (g *Guard) Active() bool {
	return g.allowed != nil || g.blocked != nil || g.requests != nil || g.failures != nil
}

// shouldBypass reports whether the IP skips all checks. Unparsable addresses
// (e.g. unix socket peers) and loopback addresses are always trusted, because
// internal components depend on them.
func (g *Guard) shouldBypass(ip net.IP) bool {
	return ip == nil || ip.IsLoopback()
}

// IPAllowed checks the client IP against the blocked and allowed network lists.
func (g *Guard) IPAllowed(ip net.IP) bool {
	if g.shouldBypass(ip) {
		return true
	}
	if g.blocked.MatchIPAddr(ip) { // MatchIPAddr is nil-safe
		return false
	}
	if g.allowed != nil && !g.allowed.MatchIPAddr(ip) {
		return false
	}
	return true
}

// AllowRequest consumes one rate limit slot for the IP. When the limit is
// exceeded it returns false and the time the client should wait before retrying.
func (g *Guard) AllowRequest(ip net.IP) (ok bool, retryAfter time.Duration) {
	if g.requests == nil || g.shouldBypass(ip) {
		return true, 0
	}
	count, retryAfter := g.requests.incr(ip.String(), time.Now())
	if count > g.cfg.RateLimitRequests {
		return false, retryAfter
	}
	return true, 0
}

// IsBanned reports whether the IP is currently banned because of repeated
// authentication failures, and for how long the ban still lasts.
func (g *Guard) IsBanned(ip net.IP) (banned bool, retryAfter time.Duration) {
	if g.failures == nil || g.shouldBypass(ip) {
		return false, 0
	}
	return g.failures.isBanned(ip.String(), time.Now())
}

// RecordAuthFailure records a failed authentication attempt from remoteAddr,
// banning the IP when it exceeds the configured failure budget.
func (g *Guard) RecordAuthFailure(remoteAddr string) {
	ip := ParseRemoteIP(remoteAddr)
	if g.failures == nil || g.shouldBypass(ip) {
		return
	}
	if count, newlyBanned := g.failures.recordFailure(ip.String(), time.Now()); newlyBanned {
		log.Warn("netguard: temporarily banning %s for %v after %d failed authentication attempts", ip, g.cfg.AuthBanDuration, count)
	}
}

// ResetAuthFailures clears the failure counter of remoteAddr, it should be
// called after a successful authentication so that shared (NAT) addresses are
// not penalized by sporadic typos.
func (g *Guard) ResetAuthFailures(remoteAddr string) {
	ip := ParseRemoteIP(remoteAddr)
	if g.failures == nil || g.shouldBypass(ip) {
		return
	}
	g.failures.reset(ip.String())
}

// ParseRemoteIP parses the IP part of a http.Request.RemoteAddr like
// "192.0.2.1:1234" or "[2001:db8::1]:1234". It returns nil for non IP based
// addresses (e.g. unix sockets).
func ParseRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

var defaultGuard atomic.Pointer[Guard]

// Init creates the process-wide Guard from the given config and returns it.
func Init(cfg Config) *Guard {
	g := NewGuard(cfg)
	defaultGuard.Store(g)
	return g
}

// RecordAuthFailure records a failed authentication attempt on the
// process-wide Guard, it is a no-op when netguard is not initialized.
func RecordAuthFailure(remoteAddr string) {
	if g := defaultGuard.Load(); g != nil {
		g.RecordAuthFailure(remoteAddr)
	}
}

// ResetAuthFailures clears the failure counter on the process-wide Guard, it
// is a no-op when netguard is not initialized.
func ResetAuthFailures(remoteAddr string) {
	if g := defaultGuard.Load(); g != nil {
		g.ResetAuthFailures(remoteAddr)
	}
}
