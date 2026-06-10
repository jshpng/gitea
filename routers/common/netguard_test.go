// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitea.dev/modules/netguard"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func netguardServe(handler func(http.Handler) http.Handler, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	resp := httptest.NewRecorder()
	handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(resp, req)
	return resp
}

func TestNetworkGuardHandlerDisabled(t *testing.T) {
	defer test.MockVariableValue(&setting.Security.Network)()
	setting.Security.Network.AllowedNetworks = ""
	setting.Security.Network.BlockedNetworks = ""
	setting.Security.Network.RateLimitEnabled = false
	setting.Security.Network.AuthAutoBanEnabled = false
	assert.Nil(t, NetworkGuardHandler())
}

func TestNetworkGuardHandlerIPFilter(t *testing.T) {
	defer test.MockVariableValue(&setting.Security.Network)()
	setting.Security.Network.AllowedNetworks = "10.0.0.0/8"
	setting.Security.Network.BlockedNetworks = "10.9.0.0/16"
	handler := NetworkGuardHandler()
	require.NotNil(t, handler)

	assert.Equal(t, http.StatusOK, netguardServe(handler, "10.1.2.3:4567").Code)
	assert.Equal(t, http.StatusForbidden, netguardServe(handler, "8.8.8.8:4567").Code)
	assert.Equal(t, http.StatusForbidden, netguardServe(handler, "10.9.1.1:4567").Code)
	// loopback always bypasses the filter
	assert.Equal(t, http.StatusOK, netguardServe(handler, "127.0.0.1:4567").Code)
}

func TestNetworkGuardHandlerRateLimit(t *testing.T) {
	defer test.MockVariableValue(&setting.Security.Network)()
	setting.Security.Network.RateLimitEnabled = true
	setting.Security.Network.RateLimitRequests = 2
	setting.Security.Network.RateLimitWindow = time.Hour
	handler := NetworkGuardHandler()
	require.NotNil(t, handler)

	assert.Equal(t, http.StatusOK, netguardServe(handler, "192.0.2.1:1000").Code)
	assert.Equal(t, http.StatusOK, netguardServe(handler, "192.0.2.1:1001").Code)
	resp := netguardServe(handler, "192.0.2.1:1002")
	assert.Equal(t, http.StatusTooManyRequests, resp.Code)
	assert.NotEmpty(t, resp.Header().Get("Retry-After"))
	// other clients are unaffected
	assert.Equal(t, http.StatusOK, netguardServe(handler, "192.0.2.2:1000").Code)
}

func TestNetworkGuardHandlerAuthAutoBan(t *testing.T) {
	defer test.MockVariableValue(&setting.Security.Network)()
	setting.Security.Network.AuthAutoBanEnabled = true
	setting.Security.Network.AuthBanMaxFailures = 2
	setting.Security.Network.AuthBanWindow = time.Hour
	setting.Security.Network.AuthBanDuration = time.Hour
	handler := NetworkGuardHandler()
	require.NotNil(t, handler)

	assert.Equal(t, http.StatusOK, netguardServe(handler, "192.0.2.1:1000").Code)

	// the failures recorded by the auth code paths feed the process-wide guard created by NetworkGuardHandler
	netguard.RecordAuthFailure("192.0.2.1:1001")
	netguard.RecordAuthFailure("192.0.2.1:1002")

	resp := netguardServe(handler, "192.0.2.1:1003")
	assert.Equal(t, http.StatusTooManyRequests, resp.Code)
	assert.NotEmpty(t, resp.Header().Get("Retry-After"))

	// a successful authentication clears the ban
	netguard.ResetAuthFailures("192.0.2.1:1004")
	assert.Equal(t, http.StatusOK, netguardServe(handler, "192.0.2.1:1005").Code)
}

func TestSecurityHeadersHandlerStrictHeaders(t *testing.T) {
	defer test.MockVariableValue(&setting.Security.HSTSMaxAge, 31536000)()
	defer test.MockVariableValue(&setting.Security.HSTSIncludeSubdomains, true)()
	defer test.MockVariableValue(&setting.Security.HSTSPreload, true)()
	defer test.MockVariableValue(&setting.Security.ReferrerPolicy, "no-referrer")()
	defer test.MockVariableValue(&setting.Security.PermissionsPolicy, "camera=(), microphone=()")()

	resp := netguardServe(SecurityHeadersHandler(), "192.0.2.1:1000")
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", resp.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "no-referrer", resp.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=(), microphone=()", resp.Header().Get("Permissions-Policy"))
}
