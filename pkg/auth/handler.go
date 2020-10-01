package auth

import (
	"encoding/json"
	"github.com/arschles/go-bindata-html-template"
	"net/http"
	"strings"
)

type ViewPack struct {
	Router    Router
	Providers []ProviderLink
	Params    interface{}
}

func (a *Auth) Handle(next http.Handler) http.Handler {
	routes := a.DefaultRouter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// AUTHORIZE (VIEW)
		if strings.HasPrefix(r.URL.Path, routes.AuthorizePath) && r.Method == "get" {
			params := struct {
				ClientID    string
				RedirectURI string
				Scope       string
				State       string
			}{
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
			}

			viewPack := ViewPack{
				routes,
				a.DefaultProviders(string(state)),
				params,
			}

			viewPack.Router.RegisterPath = a.path(routes.RegisterPath, viewPack.Router.Params)
			viewPack.Router.StatePath = a.path(routes.StatePath, viewPack.Router.Params, "action=recovery")

			a.serveTemplate(w, viewPack, files...)
		} else

		// AUTHORIZE SUBMIT
		if strings.HasPrefix(r.URL.Path, routes.AuthorizePath) && r.Method == "post" {
			if err := a.server.HandleAuthorizeRequest(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else

		// TOKEN
		if strings.HasPrefix(r.URL.Path, routes.TokenPath) && r.Method == "post" {
			if err := a.server.HandleTokenRequest(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else

		// PROVIDERS
		if strings.HasPrefix(r.URL.Path, "routes") && r.Method == "post" {
			//	userInfo := struct {
			//		ID, Email string
			//		Verified  bool
			//	}{}
			//
			//	var state oauth.AuthorizeParams
			//	if err := json.Unmarshal([]byte(params.State), &state); err != nil {
			//		return oauth.NewProviderInternalServerError().WithPayload(err.Error())
			//	}
			//
			//	switch params.Provider {
			//	case "google":
			//		var info struct {
			//			ID       string
			//			Email    string
			//			Verified bool `json:"verified_email"`
			//		}
			//
			//		if err := a.OauthUserInfo(params.Provider, params.Code, &info); err != nil {
			//			return oauth.NewProviderInternalServerError().WithPayload(err.Error())
			//		}
			//
			//		userInfo.ID = info.ID
			//		userInfo.Email = info.Email
			//		userInfo.Verified = info.Verified
			//	default:
			//		return oauth.NewProviderInternalServerError().WithPayload("no configuration for provider: " + params.Provider)
			//	}
			//
			//	var (
			//		user *User
			//		err  error
			//	)
			//
			//	if user, err = a.GetUserByEmail(userInfo.Email, nil); err != nil {
			//		if user, err = a.createUser(userInfo.Email, userInfo.ID, false, userInfo.Verified); err != nil {
			//			return oauth.NewProviderInternalServerError().WithPayload(err.Error())
			//		}
			//	} else {
			//		if user, err = a.updateUserPassword(user, strfmt.Password(userInfo.ID)); err != nil {
			//			return session.NewRecoverySubmitInternalServerError().WithPayload(err.Error())
			//		}
			//	}
			//
			//	var values = url.Values(map[string][]string{
			//		"response_type": {"code"},
			//		"redirect_uri":  {state.RedirectURI},
			//		"client_id":     {state.ClientID},
			//		"state":         {state.State},
			//		"scope":         {state.Scope},
			//		"username":      {userInfo.Email},
			//		"password":      {userInfo.ID},
			//	})
			//
			//	request := &http.Request{Form: values, Method: "POST"}
			//
			//	return middleware.ResponderFunc(func(w http.ResponseWriter, p runtime.Producer) {
			//		if err := a.HandleAuthorizeRequest(w, request); err != nil {
			//			http.Error(w, "this is the error"+err.Error(), 500)
			//		}
			//	})
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
	//		http.Redirect(w, params.HTTPRequest, url, http.StatusSeeOther)
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
	//	viewPack.Router.AuthorizePath = a.authorizePath(string(viewPack.Router.Params))
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
	//		http.Redirect(w, params.HTTPRequest, url, http.StatusSeeOther)
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
	//		http.Redirect(w, params.HTTPRequest, url, http.StatusSeeOther)
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
	//	viewPack.Router.AuthorizePath = a.authorizePath(string(viewPack.Router.Params))
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
	//		http.Redirect(w, params.HTTPRequest, url, http.StatusSeeOther)
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
	ts, err := template.New("tmpl", Asset).ParseFiles(files...)
	//ts, err := htmlt.ParseFiles(files...)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := ts.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
