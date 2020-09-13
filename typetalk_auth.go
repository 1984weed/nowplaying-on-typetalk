package main

import (
	"context"
	"errors"
	"net/http"

	v1 "github.com/nulab/go-typetalk/typetalk/v1"
	"golang.org/x/oauth2"
)

const (
	// AuthURL is the URL to Typetalk Accounts Service's OAuth2 endpoint.
	AuthURL = "https://typetalk.com/oauth2/authorize"
	// TokenURL is the URL to the Typetalk Accounts Service's OAuth2
	// token endpoint.
	TokenURL = "https://typetalk.com/oauth2/access_token"
)

// Scopes let you specify exactly which types of data your application wants to access.
// The set of scopes you pass in your authentication request determines what access the
// permissions the user is asked to grant.
const (
	// ScopeMy seeks write/read access to profile
	ScopeMy = "my"
)

// Authenticator provides convenience functions for implementing the OAuth2 flow.
// You should always use `NewAuthenticator` to make them.
//
// Example:
//
//     a := spotify.NewAuthenticator(redirectURL, spotify.ScopeUserLibaryRead, spotify.ScopeUserFollowRead)
//     // direct user to Spotify to log in
//     http.Redirect(w, r, a.AuthURL("state-string"), http.StatusFound)
//
//     // then, in redirect handler:
//     token, err := a.Token(state, r)
//     client := a.NewClient(token)
//
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

// AuthURL returns a URL to the the Typetalk Accounts Service's OAuth2 endpoint.
func (a Authenticator) AuthURL(state string) string {
	return a.config.AuthCodeURL(state)
}

// Token pulls an authorization code from an HTTP request and attempts to exchange
// it for an access token.  The standard use case is to call Token from the handler
// that handles requests to your application's redirect URL.
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
		return nil, errors.New("spotify: redirect state parameter doesn't match")
	}
	return a.config.Exchange(a.context, code)
}

// NewClient creates a Client that will use the specified access token for its API requests.
func (a Authenticator) NewClient(token *oauth2.Token) *v1.Client {
	httpClient := a.config.Client(a.context, token)
	return v1.NewClient(httpClient)
	// return v1.Client{
	// 	http:    client,
	// 	baseURL: baseAddress,
	// }
}

// // Token gets the client's current token.
func (a Authenticator) RenewToken(token *oauth2.Token) (*oauth2.Token, error) {
	return a.config.TokenSource(a.context, token).Token()
}
