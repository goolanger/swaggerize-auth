package auth

import (
	"fmt"
	"strings"
)

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
	base := "/auth"

	return Router{
		AppName:                     a.Name,
		OauthAuthorizePath:          a.path(base+"/oauth/authorize", params...),
		OauthProviders:              a.path(base+"/oauth/providers", params...),
		OauthTokenPath:              a.path(base+"/oauth/token", params...),
		SessionRecoveryPath:         a.path(base+"/session/recovery", params...),
		SessionRegisterPath:         a.path(base+"/session/register", params...),
		SessionRegisterActivatePath: a.path(base+"/session/register/activate", params...),
		SessionStatePath:            a.path(base+"/session/state", params...),
		SessionStateMessagePath:     a.path(base+"/session/state/message", params...),
		ScopeInfoPath:               a.path(base+"/scope/info", params...),
		SpecsPath:                   a.path(base + "/specs"),
		SpecsDocsPath:               a.path(base + "/docs"),
		Params:                      strings.Join(params, "&"),
	}
}

func (a *Auth) path(path string, params ...string) string {
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	return path
}

// HTML FOLDER

const HtmlFolder = "pkg/auth/html/"

func (a *Auth) viewPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + a.Template + "/views" + page
}

func (a *Auth) mailPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + a.Template + "/mail" + page
}
