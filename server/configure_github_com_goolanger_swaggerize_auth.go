// This file is safe to edit. Once it exists it will not be overwritten

package server

import (
	"crypto/tls"
	"github.com/goolanger/swaggerize-auth/pkg"
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/goolanger/swaggerize-auth/models"
	"github.com/goolanger/swaggerize-auth/server/operations"
	"github.com/goolanger/swaggerize-auth/server/operations/oauth"
	"github.com/goolanger/swaggerize-auth/server/operations/scopes"
	"github.com/goolanger/swaggerize-auth/server/operations/session"
)

//go:generate swagger generate server --target ..\..\swaggerize-auth --name GithubComGoolangerSwaggerizeAuth --spec ..\swagger.yaml --server-package server --principal models.Claims

var conf *pkg.Config

func init() {
	var err error

	if conf, err = pkg.LoadConfig("config/development.conf"); err != nil {
		panic(err)
	}

	if err = conf.Oauth.Init(&conf.Database, &conf.Mailer); err != nil {
		panic(err)
	}
}

func configureFlags(api *operations.GithubComGoolangerSwaggerizeAuthAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.GithubComGoolangerSwaggerizeAuthAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UrlformConsumer = runtime.DiscardConsumer

	api.HTMLProducer = runtime.ProducerFunc(func(w io.Writer, data interface{}) error {
		return errors.NotImplemented("html producer has not yet been implemented")
	})
	api.JSONProducer = runtime.JSONProducer()

	// Applies when the "Authorization" header is set
	api.BearerAuth = func(token string) (*models.Claims, error) {
		if claims, err := conf.Oauth.Decode(token); err != nil {
			return nil, err
		} else {
			return &models.Claims{
				ID:     claims.ID,
				Scopes: claims.Scopes,
			}, nil
		}
	}

	// Applies when the "access_token" query is set
	api.ScopedAuth = func(token string) (*models.Claims, error) {
		if claims, err := conf.Oauth.Decode(token); err != nil {
			return nil, err
		} else {
			return &models.Claims{
				ID:     claims.ID,
				Scopes: claims.Scopes,
			}, nil
		}
	}

	// Set your custom authorizer if needed. Default one is security.Authorized()
	// Expected interface runtime.Authorizer
	//
	// Example:
	// api.APIAuthorizer = security.Authorized()
	if api.OauthAuthorizeHandler == nil {
		api.OauthAuthorizeHandler = oauth.AuthorizeHandlerFunc(func(params oauth.AuthorizeParams) middleware.Responder {
			return middleware.NotImplemented("operation oauth.Authorize has not yet been implemented")
		})
	}
	if api.OauthAuthorizeSubmitHandler == nil {
		api.OauthAuthorizeSubmitHandler = oauth.AuthorizeSubmitHandlerFunc(func(params oauth.AuthorizeSubmitParams) middleware.Responder {
			return middleware.NotImplemented("operation oauth.AuthorizeSubmit has not yet been implemented")
		})
	}
	if api.ScopesInfoHandler == nil {
		api.ScopesInfoHandler = scopes.InfoHandlerFunc(func(params scopes.InfoParams, principal *models.Claims) middleware.Responder {
			return middleware.NotImplemented("operation scopes.Info has not yet been implemented")
		})
	}
	if api.OauthProviderHandler == nil {
		api.OauthProviderHandler = oauth.ProviderHandlerFunc(func(params oauth.ProviderParams) middleware.Responder {
			return middleware.NotImplemented("operation oauth.Provider has not yet been implemented")
		})
	}
	if api.SessionRecoveryHandler == nil {
		api.SessionRecoveryHandler = session.RecoveryHandlerFunc(func(params session.RecoveryParams) middleware.Responder {
			return middleware.NotImplemented("operation session.Recovery has not yet been implemented")
		})
	}
	if api.SessionRecoverySubmitHandler == nil {
		api.SessionRecoverySubmitHandler = session.RecoverySubmitHandlerFunc(func(params session.RecoverySubmitParams) middleware.Responder {
			return middleware.NotImplemented("operation session.RecoverySubmit has not yet been implemented")
		})
	}
	if api.SessionRegisterHandler == nil {
		api.SessionRegisterHandler = session.RegisterHandlerFunc(func(params session.RegisterParams) middleware.Responder {
			return middleware.NotImplemented("operation session.Register has not yet been implemented")
		})
	}
	if api.SessionRegisterActivateHandler == nil {
		api.SessionRegisterActivateHandler = session.RegisterActivateHandlerFunc(func(params session.RegisterActivateParams) middleware.Responder {
			return middleware.NotImplemented("operation session.RegisterActivate has not yet been implemented")
		})
	}
	if api.SessionRegisterSubmitHandler == nil {
		api.SessionRegisterSubmitHandler = session.RegisterSubmitHandlerFunc(func(params session.RegisterSubmitParams) middleware.Responder {
			return middleware.NotImplemented("operation session.RegisterSubmit has not yet been implemented")
		})
	}
	if api.SessionStateHandler == nil {
		api.SessionStateHandler = session.StateHandlerFunc(func(params session.StateParams) middleware.Responder {
			return middleware.NotImplemented("operation session.State has not yet been implemented")
		})
	}
	if api.SessionStateMessageHandler == nil {
		api.SessionStateMessageHandler = session.StateMessageHandlerFunc(func(params session.StateMessageParams) middleware.Responder {
			return middleware.NotImplemented("operation session.StateMessage has not yet been implemented")
		})
	}
	if api.SessionStateSubmitHandler == nil {
		api.SessionStateSubmitHandler = session.StateSubmitHandlerFunc(func(params session.StateSubmitParams) middleware.Responder {
			return middleware.NotImplemented("operation session.StateSubmit has not yet been implemented")
		})
	}
	if api.OauthTokenHandler == nil {
		api.OauthTokenHandler = oauth.TokenHandlerFunc(func(params oauth.TokenParams) middleware.Responder {
			return middleware.NotImplemented("operation oauth.Token has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return conf.Oauth.Handle(handler)
}
