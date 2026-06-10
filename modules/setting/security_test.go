// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSecurityNetworkFrom(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := NewConfigProviderFromData(``)
		require.NoError(t, err)
		loadSecurityNetworkFrom(cfg)

		assert.Empty(t, Security.Network.AllowedNetworks)
		assert.Empty(t, Security.Network.BlockedNetworks)
		assert.False(t, Security.Network.RateLimitEnabled)
		assert.Equal(t, 300, Security.Network.RateLimitRequests)
		assert.Equal(t, time.Minute, Security.Network.RateLimitWindow)
		assert.False(t, Security.Network.AuthAutoBanEnabled)
		assert.Equal(t, 10, Security.Network.AuthBanMaxFailures)
		assert.Equal(t, 10*time.Minute, Security.Network.AuthBanWindow)
		assert.Equal(t, 15*time.Minute, Security.Network.AuthBanDuration)
	})

	t.Run("configured", func(t *testing.T) {
		cfg, err := NewConfigProviderFromData(`
[security.network]
ALLOWED_NETWORKS = 10.0.0.0/8, private
BLOCKED_NETWORKS = 203.0.113.0/24
RATE_LIMIT_ENABLED = true
RATE_LIMIT_REQUESTS = 50
RATE_LIMIT_WINDOW = 30s
AUTH_AUTO_BAN_ENABLED = true
AUTH_BAN_MAX_FAILURES = 5
AUTH_BAN_WINDOW = 5m
AUTH_BAN_DURATION = 1h
`)
		require.NoError(t, err)
		loadSecurityNetworkFrom(cfg)

		assert.Equal(t, "10.0.0.0/8, private", Security.Network.AllowedNetworks)
		assert.Equal(t, "203.0.113.0/24", Security.Network.BlockedNetworks)
		assert.True(t, Security.Network.RateLimitEnabled)
		assert.Equal(t, 50, Security.Network.RateLimitRequests)
		assert.Equal(t, 30*time.Second, Security.Network.RateLimitWindow)
		assert.True(t, Security.Network.AuthAutoBanEnabled)
		assert.Equal(t, 5, Security.Network.AuthBanMaxFailures)
		assert.Equal(t, 5*time.Minute, Security.Network.AuthBanWindow)
		assert.Equal(t, time.Hour, Security.Network.AuthBanDuration)
	})
}
