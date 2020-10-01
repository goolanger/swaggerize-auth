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
	AuthorizePath string

	// token
	TokenPath string

	// recovery
	RecoveryPath string

	// register
	RegisterPath string

	// state
	StatePath string

	// state message
	StateMessagePath string

	// params
	Params string
}

func (a *Auth) DefaultRouter(params ...string) Router {
	return Router{
		AppName:          "Name",
		AuthorizePath:    a.path("/api/oauth/authorize", params...),
		TokenPath:        a.path("/api/oauth/token", params...),
		RecoveryPath:     a.path("/api/session/recovery", params...),
		RegisterPath:     a.path("/api/session/register", params...),
		StatePath:        a.path("/api/session/state", params...),
		StateMessagePath: a.path("/api/session/state/message", params...),
		Params:           strings.Join(params, "&"),
	}
}

// PRIVATE
func (a *Auth) path(path string, params ...string) string {
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	return path
}

// HTML
func (a *Auth) viewPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + "/views/" + a.Template + page
}

func (a *Auth) mailPage(format string, args ...interface{}) string {
	page := fmt.Sprintf(format, args...)
	return HtmlFolder + "/mail/" + a.Template + page
}
