package auth

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/goolanger/swaggerize-auth/pkg/db"
	"github.com/goolanger/swaggerize-auth/pkg/mail"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
)

type Auth struct {
	ClientId     string              `yaml:"clientid"`
	ClientSecret string              `yaml:"clientsecret"`
	ClientDomain string              `yaml:"domain"`
	SecretKey    string              `yaml:"secretkey"`
	Template     string              `yaml:"template"`
	Providers    map[string]Provider `yaml:"providers"`

	server *server.Server

	mailer     mail.Mailer
	connection db.Connection
}

func (a *Auth) Init(connection db.Connection, mailer mail.Mailer) error {
	// Init Db Connection
	a.connection = connection
	if err := a.connection.Connect(); err != nil {
		return err
	}

	// Init Mailer
	a.mailer = mailer
	if err := a.mailer.Init(); err != nil {
		return err
	}

	if err := a.connection.Execute().AutoMigrate(&User{}); err != nil {
		return err
	}

	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	manager.SetValidateURIHandler(func(baseURI, redirectURI string) error {
		return nil
	})

	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("HS256", []byte(a.SecretKey), jwt.SigningMethodHS512))

	clientStore := store.NewClientStore()
	err := clientStore.Set(a.ClientId, &models.Client{
		ID:     a.ClientId,
		Secret: a.ClientSecret,
		Domain: a.ClientDomain,
	})

	if err != nil {
		return err
	}

	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetPasswordAuthorizationHandler(a.PasswordAuthorizationHandler())
	srv.SetUserAuthorizationHandler(a.UserAuthorizeHandler())

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	a.server = srv

	return nil
}

func (a *Auth) UserAuthorizeHandler() server.UserAuthorizationHandler {
	return func(w http.ResponseWriter, r *http.Request) (userId string, err error) {
		return a.PasswordAuthorizationHandler()(
			r.Form.Get("username"),
			r.Form.Get("password"),
		)
	}
}

//TODO: REFACTOR AND TEST
func (a *Auth) PasswordAuthorizationHandler() server.PasswordAuthorizationHandler {
	return func(username, password string) (userID string, err error) {
		var user *User

		user, err = GetUserByEmail(a.connection, username)
		if err != nil {
			return
		}

		if !user.Verified {
			_ = a.ActivateAccount(username)
			err = errors.New("user account have not being verified")
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			return
		}

		return strconv.FormatInt(user.ID, 10), nil
	}
}
