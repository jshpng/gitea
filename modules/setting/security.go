// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net/url"
	"os"
	"strings"
	"time"

	"gitea.dev/modules/auth/password/hash"
	"gitea.dev/modules/generate"
	"gitea.dev/modules/log"
)

// Security settings
var Security = struct {
	// TODO: move more settings to this struct in future
	XFrameOptions       string
	XContentTypeOptions string

	// Strict transport and content security headers, all of them are only sent when configured.
	HSTSMaxAge            int // seconds, 0 disables the Strict-Transport-Security header
	HSTSIncludeSubdomains bool
	HSTSPreload           bool
	ReferrerPolicy        string // empty disables the Referrer-Policy header
	PermissionsPolicy     string // empty disables the Permissions-Policy header

	// Network contains the "[security.network]" settings for protecting
	// instances exposed to untrusted networks, see modules/netguard.
	Network struct {
		AllowedNetworks    string
		BlockedNetworks    string
		RateLimitEnabled   bool
		RateLimitRequests  int
		RateLimitWindow    time.Duration
		AuthAutoBanEnabled bool
		AuthBanMaxFailures int
		AuthBanWindow      time.Duration
		AuthBanDuration    time.Duration
	}
}{
	XFrameOptions:       "SAMEORIGIN",
	XContentTypeOptions: "nosniff",
}

var (
	InstallLock                        bool
	SecretKey                          string
	InternalToken                      string // internal access token
	LogInRememberDays                  int
	CookieRememberName                 string
	ReverseProxyAuthUser               string
	ReverseProxyAuthEmail              string
	ReverseProxyAuthFullName           string
	ReverseProxyLimit                  int
	ReverseProxyLogoutRedirect         string
	ReverseProxyTrustedProxies         []string
	MinPasswordLength                  int
	ImportLocalPaths                   bool
	DisableGitHooks                    = true
	DisableWebhooks                    bool
	OnlyAllowPushIfGiteaEnvironmentSet bool
	PasswordComplexity                 []string
	PasswordHashAlgo                   string
	PasswordCheckPwn                   bool
	SuccessfulTokensCacheSize          int
	DisableQueryAuthToken              bool
	RecordUserSignupMetadata           = false
	TwoFactorAuthEnforced              = false
)

// loadSecret load the secret from ini by uriKey or verbatimKey, only one of them could be set
// If the secret is loaded from uriKey (file), the file should be non-empty, to guarantee the behavior stable and clear.
func loadSecret(sec ConfigSection, uriKey, verbatimKey string) string {
	// don't allow setting both URI and verbatim string
	uri := sec.Key(uriKey).String()
	verbatim := sec.Key(verbatimKey).String()
	if uri != "" && verbatim != "" {
		log.Fatal("Cannot specify both %s and %s", uriKey, verbatimKey)
	}

	// if we have no URI, use verbatim
	if uri == "" {
		return verbatim
	}

	tempURI, err := url.Parse(uri)
	if err != nil {
		log.Fatal("Failed to parse %s (%s): %v", uriKey, uri, err)
	}
	switch tempURI.Scheme {
	case "file":
		buf, err := os.ReadFile(tempURI.RequestURI())
		if err != nil {
			log.Fatal("Failed to read %s (%s): %v", uriKey, tempURI.RequestURI(), err)
		}
		val := strings.TrimSpace(string(buf))
		if val == "" {
			// The file shouldn't be empty, otherwise we can not know whether the user has ever set the KEY or KEY_URI
			// For example: if INTERNAL_TOKEN_URI=file:///empty-file,
			// Then if the token is re-generated during installation and saved to INTERNAL_TOKEN
			// Then INTERNAL_TOKEN and INTERNAL_TOKEN_URI both exist, that's a fatal error (they shouldn't)
			log.Fatal("Failed to read %s (%s): the file is empty", uriKey, tempURI.RequestURI())
		}
		return val

	// only file URIs are allowed
	default:
		log.Fatal("Unsupported URI-Scheme %q (%q = %q)", tempURI.Scheme, uriKey, uri)
		return ""
	}
}

// generateSaveInternalToken generates and saves the internal token to app.ini
func generateSaveInternalToken(rootCfg ConfigProvider) {
	token, err := generate.NewInternalToken()
	if err != nil {
		log.Fatal("Error generate internal token: %v", err)
	}

	InternalToken = token
	saveCfg, err := rootCfg.PrepareSaving()
	if err != nil {
		log.Fatal("Error saving internal token: %v", err)
	}
	rootCfg.Section("security").Key("INTERNAL_TOKEN").SetValue(token)
	saveCfg.Section("security").Key("INTERNAL_TOKEN").SetValue(token)
	if err = saveCfg.Save(); err != nil {
		log.Fatal("Error saving internal token: %v", err)
	}
}

func loadSecurityFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("security")
	LogInRememberDays = sec.Key("LOGIN_REMEMBER_DAYS").MustInt(31)
	SecretKey = loadSecret(sec, "SECRET_KEY_URI", "SECRET_KEY")
	if SecretKey == "" {
		// FIXME: https://github.com/go-gitea/gitea/issues/16832
		// Until it supports rotating an existing secret key, we shouldn't move users off of the widely used default value
		SecretKey = "!#@FDEWREWR&*("
	}

	CookieRememberName = sec.Key("COOKIE_REMEMBER_NAME").MustString("gitea_incredible")

	ReverseProxyAuthUser = sec.Key("REVERSE_PROXY_AUTHENTICATION_USER").MustString("X-WEBAUTH-USER")
	ReverseProxyAuthEmail = sec.Key("REVERSE_PROXY_AUTHENTICATION_EMAIL").MustString("X-WEBAUTH-EMAIL")
	ReverseProxyAuthFullName = sec.Key("REVERSE_PROXY_AUTHENTICATION_FULL_NAME").MustString("X-WEBAUTH-FULLNAME")

	ReverseProxyLimit = sec.Key("REVERSE_PROXY_LIMIT").MustInt(1)
	ReverseProxyLogoutRedirect = sec.Key("REVERSE_PROXY_LOGOUT_REDIRECT").String()
	ReverseProxyTrustedProxies = sec.Key("REVERSE_PROXY_TRUSTED_PROXIES").Strings(",")
	if len(ReverseProxyTrustedProxies) == 0 {
		ReverseProxyTrustedProxies = []string{"127.0.0.0/8", "::1/128"}
	}

	MinPasswordLength = sec.Key("MIN_PASSWORD_LENGTH").MustInt(8)
	ImportLocalPaths = sec.Key("IMPORT_LOCAL_PATHS").MustBool(false)
	DisableGitHooks = sec.Key("DISABLE_GIT_HOOKS").MustBool(true)
	DisableWebhooks = sec.Key("DISABLE_WEBHOOKS").MustBool(false)
	OnlyAllowPushIfGiteaEnvironmentSet = sec.Key("ONLY_ALLOW_PUSH_IF_GITEA_ENVIRONMENT_SET").MustBool(true)

	// Ensure that the provided default hash algorithm is a valid hash algorithm
	var algorithm *hash.PasswordHashAlgorithm
	PasswordHashAlgo, algorithm = hash.SetDefaultPasswordHashAlgorithm(sec.Key("PASSWORD_HASH_ALGO").MustString(""))
	if algorithm == nil {
		log.Fatal("The provided password hash algorithm was invalid: %s", sec.Key("PASSWORD_HASH_ALGO").MustString(""))
	}

	PasswordCheckPwn = sec.Key("PASSWORD_CHECK_PWN").MustBool(false)
	SuccessfulTokensCacheSize = sec.Key("SUCCESSFUL_TOKENS_CACHE_SIZE").MustInt(20)

	deprecatedSetting(rootCfg, "cors", "X_FRAME_OPTIONS", "security", "X_FRAME_OPTIONS", "v1.26.0")
	if sec.HasKey("X_FRAME_OPTIONS") {
		Security.XFrameOptions = sec.Key("X_FRAME_OPTIONS").MustString(Security.XFrameOptions)
	} else {
		Security.XFrameOptions = rootCfg.Section("cors").Key("X_FRAME_OPTIONS").MustString(Security.XFrameOptions)
	}

	Security.XContentTypeOptions = sec.Key("X_CONTENT_TYPE_OPTIONS").MustString(Security.XContentTypeOptions)

	twoFactorAuth := sec.Key("TWO_FACTOR_AUTH").String()
	switch twoFactorAuth {
	case "":
	case "enforced":
		TwoFactorAuthEnforced = true
	default:
		log.Fatal("Invalid two-factor auth option: %s", twoFactorAuth)
	}

	InternalToken = loadSecret(sec, "INTERNAL_TOKEN_URI", "INTERNAL_TOKEN")
	if InstallLock && InternalToken == "" {
		// if Gitea has been installed but the InternalToken hasn't been generated (upgrade from an old release), we should generate
		// some users do cluster deployment, they still depend on this auto-generating behavior.
		generateSaveInternalToken(rootCfg)
	}

	cfgdata := sec.Key("PASSWORD_COMPLEXITY").Strings(",")
	if len(cfgdata) == 0 {
		cfgdata = []string{"off"}
	}
	PasswordComplexity = make([]string, 0, len(cfgdata))
	for _, name := range cfgdata {
		name := strings.ToLower(strings.Trim(name, `"`))
		if name != "" {
			PasswordComplexity = append(PasswordComplexity, name)
		}
	}

	sectionHasDisableQueryAuthToken := sec.HasKey("DISABLE_QUERY_AUTH_TOKEN")

	// TODO: default value should be true in future releases
	DisableQueryAuthToken = sec.Key("DISABLE_QUERY_AUTH_TOKEN").MustBool(false)

	RecordUserSignupMetadata = sec.Key("RECORD_USER_SIGNUP_METADATA").MustBool(false)

	// warn if the setting is set to false explicitly
	if sectionHasDisableQueryAuthToken && !DisableQueryAuthToken {
		log.Warn("Enabling Query API Auth tokens is not recommended. DISABLE_QUERY_AUTH_TOKEN will default to true in gitea 1.23 and will be removed in gitea 1.24.")
	}

	Security.HSTSMaxAge = sec.Key("HSTS_MAX_AGE").MustInt(0)
	Security.HSTSIncludeSubdomains = sec.Key("HSTS_INCLUDE_SUBDOMAINS").MustBool(true)
	Security.HSTSPreload = sec.Key("HSTS_PRELOAD").MustBool(false)
	Security.ReferrerPolicy = sec.Key("REFERRER_POLICY").MustString("")
	Security.PermissionsPolicy = sec.Key("PERMISSIONS_POLICY").MustString("")

	loadSecurityNetworkFrom(rootCfg)
}

func loadSecurityNetworkFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("security.network")
	Security.Network.AllowedNetworks = sec.Key("ALLOWED_NETWORKS").MustString("")
	Security.Network.BlockedNetworks = sec.Key("BLOCKED_NETWORKS").MustString("")
	Security.Network.RateLimitEnabled = sec.Key("RATE_LIMIT_ENABLED").MustBool(false)
	Security.Network.RateLimitRequests = sec.Key("RATE_LIMIT_REQUESTS").MustInt(300)
	Security.Network.RateLimitWindow = sec.Key("RATE_LIMIT_WINDOW").MustDuration(time.Minute)
	Security.Network.AuthAutoBanEnabled = sec.Key("AUTH_AUTO_BAN_ENABLED").MustBool(false)
	Security.Network.AuthBanMaxFailures = sec.Key("AUTH_BAN_MAX_FAILURES").MustInt(10)
	Security.Network.AuthBanWindow = sec.Key("AUTH_BAN_WINDOW").MustDuration(10 * time.Minute)
	Security.Network.AuthBanDuration = sec.Key("AUTH_BAN_DURATION").MustDuration(15 * time.Minute)
}
