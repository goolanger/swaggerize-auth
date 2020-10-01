package main

import (
	"github.com/goolanger/swaggerize/models/document"
	"github.com/goolanger/swaggerize/models/document/licenses"
	"github.com/goolanger/swaggerize/models/model"
	params "github.com/goolanger/swaggerize/models/parameter"
	"github.com/goolanger/swaggerize/models/path"
	"github.com/goolanger/swaggerize/models/response"
	"github.com/goolanger/swaggerize/models/security"
	"github.com/goolanger/swaggerize/models/swagger"
	"github.com/goolanger/swaggerize/models/tags"
	"github.com/goolanger/swaggerize/models/types/locations"
	"github.com/goolanger/swaggerize/models/types/mimes"
	"github.com/goolanger/swaggerize/models/types/scheme"
	"github.com/goolanger/swaggerize/pkg/io"
)

func main() {
	api := swagger.New().
		Info(document.Info{
			License: licenses.Apache2,
			Contact: document.Contact{
				Name:  "Amaury",
				Url:   "https://amaurydiaz.github.io",
				Email: "amauryuh@gmail.com",
			},
			Description: "Oauth 2.0 api reference",
			Title:       "Authentication",
			Version:     "0.1.0",
		}).
		Schemes(scheme.HTTPS, scheme.HTTP)

	// Security
	scoped := api.Security(security.ApiKey("scoped").In(locations.QUERY).Key("access_token")).GetRef()

	bearer := api.Security(security.ApiKey("bearer").In(locations.HEADER).Key("Authorization")).GetRef()
	api.Secure(bearer)

	// Tags

	// Definitions
	api.Define(model.Object("Claims").Props(
		model.Property("id", model.String()),
		model.Property("scopes", model.String()),
	))

	// ROUTES
	api.Route(path.Scope("/auth", path.Inherit).Routes(
		// AUTH ROUTES
		api.Route(path.Scope("/oauth", path.Inherit).Routes(
			// AUTHORIZE
			api.Route(path.Get("/authorize", "Authorize")).
				Produces(mimes.TextHtml).
				Responds(response.Response(200, "Ok")).
				Params(
					params.Query("redirect_uri", model.String()).
						Required(true),
					params.Query("client_id", model.String()).
						Required(true),
					params.Query("state", model.String()).
						Required(true),
					params.Query("scope", model.String()).
						Required(true),
				),
			api.Route(path.Post("/authorize", "AuthorizeSubmit")).
				Consumes("application/x-www-form-urlencoded").
				Params(
					params.Form("response_type", model.Enum(model.String(), "code", "token")).
						Required(true),
					params.Form("redirect_uri", model.String()).
						Required(true),
					params.Form("client_id", model.String()).
						Required(true),
					params.Form("state", model.String()).
						Required(true),
					params.Form("scope", model.String()).
						Required(true),
					params.Form("username", model.String()).
						Required(true),
					params.Form("password", model.String()).
						Required(true),
				).Responds(
				response.Response(200, "operation success"),
			),
			// TOKEN
			api.Route(path.Post("/token", "Token")).
				Consumes("application/x-www-form-urlencoded").
				Params(
					params.Form("grant_type", model.Enum(model.String(),
						"password",
						"authorization_code",
						"client_credentials",
						"refresh_token",
					)),
					params.Form("client_id", model.String()),
					params.Form("client_secret", model.String()),
					//ClientCredentials
					params.Form("scope", model.String()),
					//AuthorizationCode
					params.Form("redirect_uri", model.String()),
					params.Form("code", model.String()),
					//PasswordCredentials
					params.Form("username", model.String()),
					params.Form("password", model.Password()),
					//Refreshing
					params.Form("refresh_token", model.String()),
				).Responds(
				response.Response(200, "operation success").
					Schema(model.Object("TokenResponse").Props(
						model.Property("access_token", model.String()),
						model.Property("refresh_token", model.String()),
						model.Property("expires_in", model.Int()),
						model.Property("scope", model.String()),
						model.Property("token_type", model.String()),
					)),
			),

			// PROVIDERS
			api.Route(path.Scope("/providers/{provider}", "Provider").Routes(
				api.Route(path.Get(path.Inherit, path.Inherit)),
			)).Params(
				params.Path("provider", model.String()),
				params.Query("code", model.String()).Required(true),
				params.Query("state", model.String()).Required(true),
			),
		)).
			Secure(security.None()).
			Tag(api.Tag(tags.New("Oauth", "Oauth 2.0 authorization protocol endpoints."))),

		// SESSION ACTIONS
		api.Route(path.Scope("/session", path.Inherit).Routes(
			// REGISTER
			api.Route(path.Scope("/register", "Register").Routes(
				api.Route(path.Get(path.Inherit, path.Inherit)).
					Produces(mimes.TextHtml).
					Params(params.Query("login-url", model.String())),
				api.Route(path.Post(path.Inherit, "Submit")).
					Produces(mimes.ApplicationJson).
					Consumes("application/x-www-form-urlencoded").
					Responds(
						response.Response(409, "conflict"),
					).
					Params(
						params.Form("email", model.String()).Required(true),
						params.Form("password", model.String()).Required(true),
					),
				api.Route(path.Get("/activate", "Activate")).
					Params(
						params.Query("token", model.String()).Required(true),
					),
			)),

			// STATES
			api.Route(path.Scope("/state", "State").Routes(
				api.Route(path.Get("/message", "Message")).
					Produces(mimes.TextHtml).
					Params(
						params.Query("action", model.Enum(model.String(), "activation", "recovery", "activated", "recovered")).
							Required(true),
					),
				api.Route(path.Scope(path.Inherit, path.Inherit).Routes(
					api.Route(path.Get(path.Inherit, path.Inherit)).
						Produces(mimes.TextHtml),
					api.Route(path.Post(path.Inherit, "Submit")).
						Produces(mimes.ApplicationJson).
						Consumes("application/x-www-form-urlencoded").
						Params(params.Form("email", model.String()).Required(true)),
				)).Params(params.Query("action", model.Enum(model.String(), "activation", "recovery")).
					Required(true)),
			)),


			// RECOVERY
			api.Route(path.Scope("/recovery", "Recovery").Routes(
				api.Route(path.Get(path.Inherit, path.Inherit)).
					Produces(mimes.TextHtml),
				api.Route(path.Post(path.Inherit, "Submit")).
					Produces(mimes.ApplicationJson).
					Consumes("application/x-www-form-urlencoded").
					Params(
						params.Form("password", model.Password()).Required(true),
					),
			)).
				Params(params.Query("token", model.String()).Required(true)),

		)).
			Tag(api.Tag(tags.New("Session", "Session actions for users."))).
			Responds(response.Response(200, "OK")).
			Secure(security.None()),

		// SCOPES
		api.Route(path.Scope("/scope", path.Inherit).Routes(
			api.Route(path.Get("/info", "Info")).
				Produces(mimes.ApplicationJson).
				Responds(
					response.Response(200, "ok").
						Schema(model.Object("UserInfo").Props(
							model.Property("id", model.String()),
							model.Property("email", model.String()),
							model.Property("verified_email", model.Boolean()),
						)),
				),
		)).
			Tag(api.Tag(tags.New("Scopes", "Oauth scopes"))).
			Secure(scoped),
		// END AUTH ROUTES
	)).
		Responds(response.Response(500, "internal server error").Schema(model.String()))

	err := io.Save(api, "swagger.yaml")
	if err != nil {
		panic(err)
	}
}
