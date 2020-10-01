package auth

import (
	"encoding/json"
	"github.com/arschles/go-bindata-html-template"
	"github.com/go-openapi/runtime/middleware"
	"github.com/goolanger/swaggerize-auth/pkg/specs"
	"net/http"
	"net/url"
	"strings"
)

type ViewPack struct {
	Router    Router
	Providers []ProviderLink
	Params    interface{}
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

func (a *Auth) Handle(next http.Handler) http.Handler {
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

			viewPack.Router.SessionStatePath = a.path(routes.SessionStatePath, "action=recovery")

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

			userInfo := struct {
				ID       string
				Email    string
				Verified bool `json:"verified_email"`
			}{}

			if err := a.OauthUserInfo(params.Provider, params.Code, &userInfo); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var (
				user *User
				err  error
			)

			if user, err = GetUserByEmail(a.connection, userInfo.Email); err != nil {
				if user, err = CreateUser(a.connection, userInfo.Email, userInfo.ID, false, userInfo.Verified); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				user.Password = userInfo.ID
				if err = UpdateUser(a.connection, user.ID, user); err != nil {
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
	//
	//api.OauthProviderHandler = oauth.ProviderHandlerFunc(func(params oauth.ProviderParams) middleware.Responder {
	//
	//})
	//
	//// RECOVERY (VIEW)
	//api.SessionRecoveryHandler = session.RecoveryHandlerFunc(func(params session.RecoveryParams) middleware.Responder {
	//	files := []string{
	//		a.viewPage("/recovery.tmpl"),
	//		a.viewPage("/base.tmpl"),
	//	}
	//
	//	viewPack := ViewPack{
	//		Router: a.DefaultRouter(params.HTTPRequest),
	//		Params: params,
	//	}
	//
	//	return serveTemplate(viewPack, files...)
	//})
	//
	//// RECOVERY SUBMIT
	//api.SessionRecoverySubmitHandler = session.RecoverySubmitHandlerFunc(func(params session.RecoverySubmitParams) middleware.Responder {
	//	userId, action, err := a.checkActionToken(params.Token)
	//	if err != nil {
	//		return session.NewRecoverySubmitInternalServerError().WithPayload(err.Error())
	//	} else if action != ActionRecovery {
	//		return session.NewRecoverySubmitInternalServerError().WithPayload("invalid action")
	//	}
	//
	//	user, err := a.GetUserById(userId)
	//	if err != nil {
	//		return session.NewRecoverySubmitInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	if _, err := a.updateUserPassword(user, params.Password); err != nil {
	//		return session.NewRecoverySubmitInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	url := a.stateMessagePath("action=recovered")
	//
	//	return middleware.ResponderFunc(func(w http.ResponseWriter, r runtime.Producer) {
	//		http.Link(w, params.HTTPRequest, url, http.StatusSeeOther)
	//	})
	//})
	//
	//// REGISTER (VIEW)
	//api.SessionRegisterHandler = session.RegisterHandlerFunc(func(params session.RegisterParams) middleware.Responder {
	//	files := []string{
	//		a.viewPage("/register.tmpl"),
	//		a.viewPage("/base.tmpl"),
	//	}
	//
	//	viewPack := ViewPack{
	//		Router: a.DefaultRouter(params.HTTPRequest),
	//		Params: params,
	//	}
	//
	//	viewPack.Router.OauthAuthorizePath = a.authorizePath(string(viewPack.Router.Params))
	//
	//	return serveTemplate(viewPack, files...)
	//})
	//
	//// REGISTER SUBMIT
	//api.SessionRegisterSubmitHandler = session.RegisterSubmitHandlerFunc(func(params session.RegisterSubmitParams) middleware.Responder {
	//	if user, _ := a.GetUserByEmail(params.Email, nil); user != nil {
	//		return session.NewRegisterSubmitConflict()
	//	}
	//
	//	if user, err := a.createUser(params.Email, params.Password, false, false); err != nil {
	//		return session.NewRegisterSubmitInternalServerError().WithPayload(err.Error())
	//	} else if err := a.ActivateAccount(user.Email); err != nil {
	//		return session.NewRegisterSubmitInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	url := a.stateMessagePath("action=activation")
	//
	//	return middleware.ResponderFunc(func(w http.ResponseWriter, r runtime.Producer) {
	//		http.Link(w, params.HTTPRequest, url, http.StatusSeeOther)
	//	})
	//})
	//
	//// REGISTER ACTIVATE
	//api.SessionRegisterActivateHandler = session.RegisterActivateHandlerFunc(func(params session.RegisterActivateParams) middleware.Responder {
	//	userId, action, err := a.checkActionToken(params.Token)
	//	if err != nil {
	//		return session.NewRegisterActivateInternalServerError().WithPayload(err.Error())
	//	} else if action != ActionActivation {
	//		return session.NewRegisterActivateInternalServerError().WithPayload("invalid action")
	//	}
	//
	//	user, err := a.GetUserById(userId)
	//	if err != nil {
	//		return session.NewRegisterActivateInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	user.Active = true
	//
	//	if err := a.Connection.Save(&user).Error; err != nil {
	//		return session.NewRegisterActivateInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	url := a.stateMessagePath("action=activated")
	//
	//	return middleware.ResponderFunc(func(w http.ResponseWriter, r runtime.Producer) {
	//		http.Link(w, params.HTTPRequest, url, http.StatusSeeOther)
	//	})
	//})
	//
	//// STATE (VIEW)
	//api.SessionStateHandler = session.StateHandlerFunc(func(params session.StateParams) middleware.Responder {
	//	files := []string{
	//		a.viewPage("/state.tmpl"),
	//		a.viewPage("/base.tmpl"),
	//	}
	//
	//	viewPack := ViewPack{
	//		Router: a.DefaultRouter(params.HTTPRequest),
	//		Params: params,
	//	}
	//
	//	viewPack.Router.OauthAuthorizePath = a.authorizePath(string(viewPack.Router.Params))
	//
	//	return serveTemplate(viewPack, files...)
	//})
	//
	//// STATE MESSAGE (VIEW)
	//api.SessionStateMessageHandler = session.StateMessageHandlerFunc(func(params session.StateMessageParams) middleware.Responder {
	//	files := []string{
	//		a.viewPage("/message.tmpl"),
	//		a.viewPage("/base.tmpl"),
	//	}
	//
	//	viewPack := ViewPack{
	//		Router: a.DefaultRouter(params.HTTPRequest),
	//		Params: params,
	//	}
	//
	//	return serveTemplate(viewPack, files...)
	//})
	//
	//// STATE SUBMIT (MAIL)
	//api.SessionStateSubmitHandler = session.StateSubmitHandlerFunc(func(params session.StateSubmitParams) middleware.Responder {
	//	if params.Action == "activation" {
	//		if err := a.ActivateAccount(params.Email); err != nil {
	//			return session.NewStateSubmitInternalServerError().WithPayload(err.Error())
	//		}
	//	} else if params.Action == "recovery" {
	//		if err := a.RecoverAccount(params.Email); err != nil {
	//			return session.NewStateSubmitInternalServerError().WithPayload(err.Error())
	//		}
	//	} else {
	//		return session.NewStateSubmitInternalServerError().WithPayload("invalid action: " + params.Action)
	//	}
	//
	//	url := a.stateMessagePath("action=" + params.Action)
	//
	//	return middleware.ResponderFunc(func(w http.ResponseWriter, r runtime.Producer) {
	//		http.Link(w, params.HTTPRequest, url, http.StatusSeeOther)
	//	})
	//})
	//
	////	SCOPE INFO
	//api.ScopesInfoHandler = scopes.InfoHandlerFunc(func(params scopes.InfoParams, claims *models.Claims) middleware.Responder {
	//	if !strings.Contains(claims.Scopes, "") {
	//		return scopes.NewInfoInternalServerError().WithPayload("unscoped request")
	//	}
	//
	//	id, err := strconv.ParseInt(claims.ID, 10, 64)
	//	if err != nil {
	//		return scopes.NewInfoInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	user, err := a.GetUserById(id)
	//	if err != nil {
	//		return scopes.NewInfoInternalServerError().WithPayload(err.Error())
	//	}
	//
	//	return scopes.NewInfoOK().WithPayload(&scopes.InfoOKBody{
	//		Email:         user.Email,
	//		ID:            claims.ID,
	//		VerifiedEmail: user.Verified,
	//	})
	//})
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
