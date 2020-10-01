package auth

import (
	"fmt"
	"strings"
)

const HtmlFolder = "pkg/auth/html"

type Router struct {

	// application name
	AppName string

	// authorize
	OauthAuthorizePath string

	// providers
	OauthProviders string

	// token
	OauthTokenPath string

	// recovery
	SessionRecoveryPath string

	// register
	SessionRegisterPath string

	// register activate
	SessionRegisterActivatePath string

	// state
	SessionStatePath string

	// state message
	SessionStateMessagePath string

	// info
	ScopeInfoPath string

	// specs
	SpecsPath string

	// specs docs
	SpecsDocsPath string

	// params
	Params string
}

func (a *Auth) DefaultRouter(params ...string) Router {
	return Router{
		AppName:                     "Name",
		OauthAuthorizePath:          a.path("/oauth/authorize", params...),
		OauthProviders:              a.path("/oauth/providers", params...),
		OauthTokenPath:              a.path("/oauth/token", params...),
		SessionRecoveryPath:         a.path("/session/recovery", params...),
		SessionRegisterPath:         a.path("/session/register", params...),
		SessionRegisterActivatePath: a.path("/session/register/activate", params...),
		SessionStatePath:            a.path("/session/state", params...),
		SessionStateMessagePath:     a.path("/session/state/message", params...),
		ScopeInfoPath:               a.path("/scope/info", params...),
		SpecsPath:                   a.path("/specs"),
		SpecsDocsPath:               a.path("/docs"),
		Params:                      strings.Join(params, "&"),
	}
}

// PRIVATE
func (a *Auth) path(path string, params ...string) string {
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	return "/auth" + path
}

// HTML
func (a *Auth) viewPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + "/views" + page
}

func (a *Auth) mailPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + "/mail" + page
}
