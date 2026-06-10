// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFeishuProviderRegistered(t *testing.T) {
	provider, ok := gothProviders["feishu"]
	require.True(t, ok)
	assert.Equal(t, "Feishu / Lark", provider.DisplayName())

	gothProvider, err := provider.CreateGothProvider("feishu", "https://example.com/user/oauth2/feishu/callback", &Source{
		ClientID:     "cli_test",
		ClientSecret: "secret",
	})
	require.NoError(t, err)
	require.NotNil(t, gothProvider)
	_, isFeishu := gothProvider.(*feishuProvider)
	assert.True(t, isFeishu)
}

func TestFeishuEnsureUserID(t *testing.T) {
	cases := []struct {
		name     string
		user     goth.User
		expected string
	}{
		{
			name:     "user_id already present",
			user:     goth.User{UserID: "uid-1", RawData: map[string]any{"data": map[string]any{"union_id": "on-1"}}},
			expected: "uid-1",
		},
		{
			name:     "fall back to union_id",
			user:     goth.User{RawData: map[string]any{"data": map[string]any{"union_id": "on-1", "open_id": "ou-1"}}},
			expected: "on-1",
		},
		{
			name:     "fall back to open_id",
			user:     goth.User{RawData: map[string]any{"data": map[string]any{"open_id": "ou-1"}}},
			expected: "ou-1",
		},
		{
			name:     "no raw data",
			user:     goth.User{},
			expected: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			feishuEnsureUserID(&c.user)
			assert.Equal(t, c.expected, c.user.UserID)
		})
	}
}
