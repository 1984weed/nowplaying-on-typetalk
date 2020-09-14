package main

import (
	"context"
	"errors"
	"net/http"

	typetalk "github.com/nulab/go-typetalk/v3/typetalk/v1"
	"golang.org/x/oauth2"
)

const (
	// AuthURL is the URL to Typetalk Accounts Service's OAuth2 endpoint.
	AuthURL = "https://typetalk.com/oauth2/authorize"
	// TokenURL is the URL to the Typetalk Accounts Service's OAuth2
	// token endpoint.
	TokenURL = "https://typetalk.com/oauth2/access_token"
)

const (
	// ScopeMy seeks write/read access to profile
	ScopeMy = "my"
)

type Authenticator struct {
	config  *oauth2.Config
	context context.Context
}

func NewAuthenticator(clientID, secretKey, redirectURL string, scopes ...string) Authenticator {
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secretKey,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
		},
	}

	tr := &http.Transport{}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: tr})
	return Authenticator{
		config:  cfg,
		context: ctx,
	}
}

func (a Authenticator) AuthURL(state string) string {
	return a.config.AuthCodeURL(state)
}

func (a Authenticator) Token(state string, r *http.Request) (*oauth2.Token, error) {
	values := r.URL.Query()
	if e := values.Get("error"); e != "" {
		return nil, errors.New("typetalk: auth failed - " + e)
	}
	code := values.Get("code")
	if code == "" {
		return nil, errors.New("typetalk: didn't get access code")
	}
	actualState := values.Get("state")
	if actualState != state {
		return nil, errors.New("redirect state parameter doesn't match")
	}
	return a.config.Exchange(a.context, code)
}

func (a Authenticator) NewClient(token *oauth2.Token) *typetalk.Client {
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.AccessToken},
	))

	return typetalk.NewClient(tc)
}

// // Token gets the client's current token.
func (a Authenticator) RenewToken(token *oauth2.Token) (*oauth2.Token, error) {
	return a.config.TokenSource(a.context, token).Token()
}

type MyProfile struct {
	Account *typetalk.Account `json:"account"`
}
