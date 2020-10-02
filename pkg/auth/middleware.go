package auth

import (
	"encoding/json"
	"github.com/arschles/go-bindata-html-template"
	"github.com/go-openapi/runtime/middleware"
	"github.com/goolanger/swaggerize-auth/pkg/specs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ViewPack struct {
	Router    Router
	Providers []ProviderLink
	Params    interface{}
}

type UserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
}

type AuthorizeParams struct {
	/*
	  Required: true
	  In: query
	*/
	ClientID string
	/*
	  Required: true
	  In: query
	*/
	RedirectURI string
	/*
	  Required: true
	  In: query
	*/
	Scope string
	/*
	  Required: true
	  In: query
	*/
	State string
}

type ProviderParams struct {
	/*
	  Required: true
	  In: query
	*/
	Code string
	/*
	  Required: true
	  In: path
	*/
	Provider string
	/*
	  Required: true
	  In: query
	*/
	State string
}

type RecoveryParams struct {
	/*
	  Required: true
	  In: query
	*/
	Token string
}

type RecoverySubmitParams struct {
	/*
	  Required: true
	  In: formData
	*/
	Password string
	/*
	  Required: true
	  In: query
	*/
	Token string
}

type RegisterSubmitParams struct {
	/*
	  Required: true
	  In: formData
	*/
	Email string
	/*
	  Required: true
	  In: formData
	*/
	Password string
}

type RegisterActivateParams struct {
	/*
	  Required: true
	  In: query
	*/
	Token string
}

type StateParams struct {
	/*
	  Required: true
	  In: query
	*/
	Action string
}

type StateMessageParams struct {
	/*
	  Required: true
	  In: query
	*/
	Action string
}

type StateSubmitParams struct {
	/*
	  Required: true
	  In: query
	*/
	Action string
	/*
	  Required: true
	  In: formData
	*/
	Email string
}

type InfoParams struct {
	/*
	  Required: true
	  In: query
	*/
	AccessToken string
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	routes := a.DefaultRouter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// AUTHORIZE (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.OauthAuthorizePath) && r.Method == "GET" {
			params := AuthorizeParams{
				ClientID:    r.FormValue("client_id"),
				RedirectURI: r.FormValue("redirect_uri"),
				Scope:       r.FormValue("scope"),
				State:       r.FormValue("state"),
			}

			files := []string{
				a.viewPage("/login.tmpl"),
				a.viewPage("/base.tmpl"),
			}

			state, err := json.Marshal(params)

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			viewPack := ViewPack{
				a.DefaultRouter(r.URL.RawQuery),
				a.DefaultProviders(string(state)),
				params,
			}

			viewPack.Router.SessionStatePath = a.path(routes.SessionStatePath, r.URL.RawQuery, "action=recovery")

			a.serveTemplate(w, viewPack, files...)
		} else

		// AUTHORIZE SUBMIT
		if strings.HasPrefix(r.URL.Path, routes.OauthAuthorizePath) && r.Method == "POST" {
			if err := a.server.HandleAuthorizeRequest(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else

		// TOKEN
		if strings.HasPrefix(r.URL.Path, routes.OauthTokenPath) && r.Method == "POST" {
			if err := a.server.HandleTokenRequest(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else

		// PROVIDERS
		if strings.HasPrefix(r.URL.Path, routes.OauthProviders) && r.Method == "GET" {
			params := ProviderParams{
				Code:     r.URL.Query().Get("code"),
				Provider: r.URL.Path[len(routes.OauthProviders)+1:],
				State:    r.URL.Query().Get("state"),
			}

			var state AuthorizeParams
			if err := json.Unmarshal([]byte(params.State), &state); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var userInfo UserInfo

			if err := a.OauthUserInfo(params.Provider, params.Code, &userInfo); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var (
				user *User
				err  error
			)

			if user, err = a.GetUserByEmail(userInfo.Email); err != nil {
				if user, err = a.CreateUser(userInfo.Email, userInfo.ID, false, userInfo.Verified); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				if user.Digest, err = a.GetDigest(userInfo.ID); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				if err = a.connection.Execute().Save(user).Error; err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}

			var values = url.Values(map[string][]string{
				"response_type": {"code"},
				"redirect_uri":  {state.RedirectURI},
				"client_id":     {state.ClientID},
				"state":         {state.State},
				"scope":         {state.Scope},
				"username":      {userInfo.Email},
				"password":      {userInfo.ID},
			})

			request := &http.Request{Form: values, Method: "POST"}

			if err := a.server.HandleAuthorizeRequest(w, request); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		} else

		// RECOVERY (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.SessionRecoveryPath) && r.Method == "GET" {
			params := RecoveryParams{
				Token: r.URL.Query().Get("token"),
			}

			files := []string{
				a.viewPage("/recovery.tmpl"),
				a.viewPage("/base.tmpl"),
			}

			viewPack := ViewPack{
				Router: a.DefaultRouter(r.URL.RawQuery),
				Params: params,
			}

			a.serveTemplate(w, viewPack, files...)
		} else

		// RECOVERY SUBMIT
		if strings.HasPrefix(r.URL.Path, routes.SessionRecoveryPath) && r.Method == "POST" {
			params := RecoverySubmitParams{
				Password: r.FormValue("password"),
				Token:    r.URL.Query().Get("token"),
			}

			userId, action, err := a.CheckActionToken(params.Token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else if action != Recovery {
				http.Error(w, "invalid action", http.StatusInternalServerError)
				return
			}

			user, err := a.GetUserById(userId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if user.Digest, err = a.GetDigest(params.Password); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if err := a.connection.Execute().Save(user).Error; err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			redirectUrl := a.path(routes.SessionStateMessagePath, "action=recovered")

			http.Redirect(w, r, redirectUrl, http.StatusSeeOther)

		} else

		// REGISTER ACTIVATE
		if strings.HasPrefix(r.URL.Path, routes.SessionRegisterActivatePath) && r.Method == "GET" {
			params := RegisterActivateParams{
				Token: r.URL.Query().Get("token"),
			}

			userId, action, err := a.CheckActionToken(params.Token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else if action != Activation {
				http.Error(w, "invalid action", http.StatusInternalServerError)
				return
			}

			user, err := a.GetUserById(userId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			user.Verified = true
			if err := a.connection.Execute().Save(user).Error; err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			redirectUrl := a.path(routes.SessionStateMessagePath, "action=activated")

			http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		} else

		// REGISTER (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.SessionRegisterPath) && r.Method == "GET" {
			files := []string{
				a.viewPage("/register.tmpl"),
				a.viewPage("/base.tmpl"),
			}

			viewPack := ViewPack{
				Router: a.DefaultRouter(r.URL.RawQuery),
			}

			a.serveTemplate(w, viewPack, files...)
		} else

		// REGISTER SUBMIT
		if strings.HasPrefix(r.URL.Path, routes.SessionRegisterPath) && r.Method == "POST" {
			params := RegisterSubmitParams{
				Email:    r.FormValue("email"),
				Password: r.FormValue("password"),
			}

			if user, _ := a.GetUserByEmail(params.Email); user != nil {
				http.Error(w, "user already register", http.StatusConflict)
				return
			}

			if user, err := a.CreateUser(params.Email, params.Password, true, false); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else if err := a.ActivateAccount(user.Email); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			redirectUrl := a.path(routes.SessionStateMessagePath, "action=activation")

			http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		} else

		// STATE MESSAGE (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.SessionStateMessagePath) && r.Method == "GET" {
			params := StateMessageParams{
				Action: r.URL.Query().Get("action"),
			}

			files := []string{
				a.viewPage("/message.tmpl"),
				a.viewPage("/base.tmpl"),
			}

			viewPack := ViewPack{
				Router: a.DefaultRouter(r.URL.RawQuery),
				Params: params,
			}

			a.serveTemplate(w, viewPack, files...)
		} else

		// STATE (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.SessionStatePath) && r.Method == "GET" {
			params := StateParams{
				Action: r.URL.Query().Get("action"),
			}

			files := []string{
				a.viewPage("/state.tmpl"),
				a.viewPage("/base.tmpl"),
			}

			viewPack := ViewPack{
				Router: a.DefaultRouter(r.URL.RawQuery),
				Params: params,
			}

			a.serveTemplate(w, viewPack, files...)
		} else

		// STATE SUBMIT (MAIL)
		if strings.HasPrefix(r.URL.Path, routes.SessionStatePath) && r.Method == "POST" {
			params := StateSubmitParams{
				Action: r.URL.Query().Get("action"),
				Email:  r.FormValue("email"),
			}

			if Action(params.Action) == Activation {
				if err := a.ActivateAccount(params.Email); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else if Action(params.Action) == Recovery {
				if err := a.RecoverAccount(params.Email); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "invalid action", http.StatusInternalServerError)
				return
			}

			redirectUrl := a.path(routes.SessionStateMessagePath, "action="+params.Action)

			http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		} else

		//	SCOPE INFO
		if strings.HasPrefix(r.URL.Path, routes.ScopeInfoPath) && r.Method == "GET" {
			params := InfoParams{
				AccessToken: r.URL.Query().Get("access_token"),
			}

			claims, err := a.Decode(params.AccessToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// TODO: Create scope
			if !strings.Contains(claims.Scopes, "") {
				http.Error(w, "invalid scope access", http.StatusForbidden)
				return
			}

			id, err := strconv.ParseInt(claims.ID, 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			user, err := a.GetUserById(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			_ = json.NewEncoder(w).Encode(UserInfo{
				ID:       strconv.FormatInt(user.ID, 10),
				Email:    user.Email,
				Verified: user.Verified,
			})
		} else

		// SPECS
		if strings.HasPrefix(r.URL.Path, routes.SpecsPath) && r.Method == "GET" {
			if _, err := w.Write(specs.MustAsset("swagger.yaml")); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else

		// SPECS DOCS
		if strings.HasPrefix(r.URL.Path, routes.SpecsDocsPath) && r.Method == "GET" {
			middleware.Redoc(middleware.RedocOpts{
				Path:    routes.SpecsDocsPath,
				SpecURL: routes.SpecsPath,
			}, nil).ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func (a *Auth) serveTemplate(w http.ResponseWriter, data interface{}, files ...string) {
	ts, err := template.New("tmpl", a.assets).ParseFiles(files...)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := ts.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
