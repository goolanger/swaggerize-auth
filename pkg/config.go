package pkg

import (
	"github.com/goolanger/swaggerize-auth/pkg/auth"
	"github.com/goolanger/swaggerize-auth/pkg/db"
	"github.com/goolanger/swaggerize-auth/pkg/mail"
	"github.com/sethvargo/go-password/password"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"time"
)

type Config struct {
	Oauth auth.Auth `yaml:"oauth"`

	Database db.Default `yaml:"db"`

	Mailer mail.Default `yaml:"mail"`
}

func LoadConfig(file string) (*Config, error) {
	var (
		data []byte
		err  error
	)

	if data, err = ioutil.ReadFile(file); err != nil {
		if data, err = DefaultConfig(file); err != nil {
			return nil, err
		}
	}

	var conf Config

	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	return &conf, nil
}

func DefaultConfig(file string) ([]byte, error) {
	clientSecret, _ := password.Generate(16, 6, 0, false, true)
	secretKey, _ := password.Generate(64, 24, 0, false, true)

	conf := Config{
		Oauth: auth.Auth{
			ClientId:     "client",
			ClientSecret: clientSecret,
			ClientDomain: "localhost",
			SecretKey:    secretKey,
			Template:     "default",
			Name:         "swaggerize",
			Providers: map[string]auth.Provider{
				"google": {
					InfoUrl: "https://www.googleapis.com/oauth2/v2/userinfo?access_token={token}",
					Config:  oauth2.Config{},
				},
			},
		},
		Database: db.Default{
			Name:    "data/db/development.sqlite",
			Handler: "sqlite",
		},
		Mailer: mail.Default{
			User:        "",
			Password:    "",
			SMTPAddress: "localhost",
			SMTPPort:    1025,
			Wait:        5 * time.Second,
			Attempts:    5,
		},
	}

	var (
		data []byte
		err  error
	)

	if data, err = yaml.Marshal(&conf); err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(file, data, 0644); err != nil {
		return nil, err
	}

	return data, nil
}
