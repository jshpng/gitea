// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/lark"
)

// feishuProvider wraps the goth "lark" provider, which talks to the
// Feishu open platform (https://open.feishu.cn).
//
// The wrapper guarantees that the fetched user always has a usable UserID for
// Gitea account linking: Feishu only returns the "user_id" field when the
// application has been granted the corresponding read permission, so when it
// is empty we fall back to the stable "union_id" or the per-app "open_id".
type feishuProvider struct {
	*lark.Provider
}

// FetchUser fetches the user from Feishu and normalizes the user ID
func (p *feishuProvider) FetchUser(session goth.Session) (goth.User, error) {
	user, err := p.Provider.FetchUser(session)
	if err != nil {
		return user, err
	}
	feishuEnsureUserID(&user)
	return user, nil
}

// feishuEnsureUserID fills goth.User.UserID from the raw Feishu response when
// the "user_id" field is not available to the application.
// The raw data is the whole Feishu response envelope: {"code":0,"msg":"...","data":{...}}
func feishuEnsureUserID(user *goth.User) {
	if user.UserID != "" {
		return
	}
	data, _ := user.RawData["data"].(map[string]any)
	for _, key := range []string{"union_id", "open_id"} {
		if v, _ := data[key].(string); v != "" {
			user.UserID = v
			return
		}
	}
}

func init() {
	RegisterGothProvider(NewSimpleProvider(
		"feishu", "Feishu / Lark", nil,
		func(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
			return &feishuProvider{Provider: lark.New(clientKey, secret, callbackURL, scopes...)}
		},
	))
}
