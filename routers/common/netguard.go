// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"
	"strconv"
	"time"

	"gitea.dev/modules/log"
	"gitea.dev/modules/netguard"
	"gitea.dev/modules/setting"
)

// NetworkGuardHandler returns a middleware which enforces the
// "[security.network]" protections (IP allow/block lists, per-IP rate limiting
// and temporary bans after repeated authentication failures) for every request.
// It returns nil when no protection is enabled.
func NetworkGuardHandler() func(http.Handler) http.Handler {
	guard := netguard.Init(netguard.Config{
		AllowedNetworks:    setting.Security.Network.AllowedNetworks,
		BlockedNetworks:    setting.Security.Network.BlockedNetworks,
		RateLimitEnabled:   setting.Security.Network.RateLimitEnabled,
		RateLimitRequests:  setting.Security.Network.RateLimitRequests,
		RateLimitWindow:    setting.Security.Network.RateLimitWindow,
		AuthAutoBanEnabled: setting.Security.Network.AuthAutoBanEnabled,
		AuthBanMaxFailures: setting.Security.Network.AuthBanMaxFailures,
		AuthBanWindow:      setting.Security.Network.AuthBanWindow,
		AuthBanDuration:    setting.Security.Network.AuthBanDuration,
	})
	if !guard.Active() {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			ip := netguard.ParseRemoteIP(req.RemoteAddr)
			if !guard.IPAllowed(ip) {
				log.Warn("netguard: blocked request to %s from %s by network access policy", req.URL.Path, req.RemoteAddr)
				http.Error(resp, "Access from your network is not allowed", http.StatusForbidden)
				return
			}
			if banned, retryAfter := guard.IsBanned(ip); banned {
				setRetryAfterHeader(resp, retryAfter)
				http.Error(resp, "Too many failed authentication attempts, please try again later", http.StatusTooManyRequests)
				return
			}
			if ok, retryAfter := guard.AllowRequest(ip); !ok {
				setRetryAfterHeader(resp, retryAfter)
				http.Error(resp, "Rate limit exceeded, please try again later", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(resp, req)
		})
	}
}

func setRetryAfterHeader(resp http.ResponseWriter, retryAfter time.Duration) {
	seconds := max(int64(retryAfter/time.Second), 1)
	resp.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
}
