package auth

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strings"
)

type State struct {

	// state
	State string

	// redirect
	Redirect string
}

type Provider struct {

	// info url
	InfoUrl string `yaml:"infourl"`

	// config
	oauth2.Config
}

func (a *Auth) OauthLink(provider, state string) (string, error) {
	providerConf, ok := a.Providers[provider]
	if !ok {
		return "", errors.New("no configuration for provider: " + provider)
	}

	return providerConf.AuthCodeURL(state), nil
}

func (a *Auth) OauthUserInfo(provider, code string, result interface{}) error {
	providerConf, ok := a.Providers[provider]
	if !ok {
		return errors.New("no configuration for provider: " + provider)
	}

	token, err := providerConf.Exchange(context.TODO(), code)
	if err != nil {
		return err
	}

	response, err := http.Get(strings.Replace(providerConf.InfoUrl, "{token}", token.AccessToken, 1))
	if err != nil {
		return err
	}

	info, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(info, result)
}

type ProviderLink struct {

	// name
	Name string

	// link
	Link string
}

func (a *Auth) DefaultProviders(state string) []ProviderLink {
	var providers []ProviderLink
	for k, _ := range a.Providers {
		if link, err := a.OauthLink(k, state); err == nil {
			providers = append(providers, ProviderLink{
				Name: k,
				Link: link,
			})
		}
	}
	return providers
}
