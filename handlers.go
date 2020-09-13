package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"text/template"
	"time"

	_ "github.com/lib/pq"

	"github.com/dgrijalva/jwt-go"
	v1 "github.com/nulab/go-typetalk/typetalk/v1"
	typetalk "github.com/nulab/go-typetalk/v3/typetalk/v1"
	"github.com/zmb3/spotify"
	"golang.org/x/oauth2"
)

var (
	sessionName = "session-token"
	state       = ""
	activeUser  = map[int]Stream{}
)

type handlers struct {
	typetalkAuth TypetalkAuthenticator
	spotifyAuth  SpotifyAuthenticator
	jwtSecret    string
	store        IStore
}

type TypetalkAuthenticator interface {
	NewClient(token *oauth2.Token) *v1.Client
	Token(state string, r *http.Request) (*oauth2.Token, error)
	AuthURL(state string) string
	RenewToken(token *oauth2.Token) (*oauth2.Token, error)
}

type SpotifyAuthenticator interface {
	Exchange(code string) (*oauth2.Token, error)
	AuthURL(state string) string
	NewClient(token *oauth2.Token) spotify.Client
}

type Oauth2Credential struct {
	ClientID    string
	SecretKey   string
	RedirectURI string
	Scope       string
}

type typtalkAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type spotifyAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string
}

func NewHandlers(typetalkAuth TypetalkAuthenticator, spotifyAuth SpotifyAuthenticator, jwtSecret string, store IStore) handlers {
	return handlers{typetalkAuth, spotifyAuth, jwtSecret, store}
}

func (h *handlers) Top(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	userID := ForContext(r.Context())

	// Guest users
	if userID == 0 {
		t, err := template.ParseFiles("index.html")

		if err != nil {
			log.Fatalln(err, "Unable to load template")
		}

		credentials := struct {
			AuthURL string
		}{
			AuthURL: h.typetalkAuth.AuthURL(state),
		}

		t.Execute(w, credentials)
		return
	}

	// Loginned users
	t, err := template.ParseFiles("index-user-page.html")
	if err != nil {
		log.Fatalln(err, "Unable to load index-user-page")
	}

	t.Execute(w, nil)
}

func (h *handlers) CheckConnectionSpotify(w http.ResponseWriter, r *http.Request) {
	userID := ForContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	// This endpoint allows only loginned users
	if userID == 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	token, err := h.store.GetSpotifyToken(userID)

	if err != nil {
		printError("Cannot get spotify token", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	result := struct {
		IsConnected bool `json:"isConnected"`
		AuthURL     string
	}{
		AuthURL: h.spotifyAuth.AuthURL(state),
	}

	// if there is not Credentials, it returns false
	if token == nil {
		result.IsConnected = false
	} else {
		// Update access token every time to prevent access token is expired
		// RefreshToken of spotify won't be expired in certain term
		sc := h.spotifyAuth.NewClient(token)
		newToken, err := sc.Token()

		if err != nil {
			printError(err)
			js, _ := json.Marshal(result)

			w.Write(js)
			return
		}

		err = h.store.UpdateSpotifyToken(userID, newToken)

		if err != nil {
			printError(err)
			js, _ := json.Marshal(result)

			w.Write(js)
			return
		}

		result.IsConnected = true
	}
	js, _ := json.Marshal(result)

	w.Write(js)
}

func (h *handlers) CheckConnectionTypetalk(w http.ResponseWriter, r *http.Request) {
	userID := ForContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	// This endpoint allows only loginned users
	if userID == 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	token, err := h.store.GetTypetalkToken(userID)

	if err != nil {
		log.Fatal("Cannot retreive users row", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	res := func() *struct {
		IsConnected bool   `json:"isConnected"`
		AuthURL     string `json:"authURL"`
	} {
		result := &struct {
			IsConnected bool   `json:"isConnected"`
			AuthURL     string `json:"authURL"`
		}{
			AuthURL: h.typetalkAuth.AuthURL(state),
		}
		// if there is not Credentials, it returns false
		if token == nil {
			return result
		}
		oldToken, err := h.store.GetTypetalkToken(userID)
		if err != nil {
			printError("Cannot retrieve typetalk token in CheckConnectionTypetalk")
			return result
		}

		// Update access token every time to prevent access token is expired
		token, err := h.typetalkAuth.RenewToken(oldToken)
		if err != nil {
			printError("Refresh token is invalid", err)
			return result
		}

		err = h.store.UpdateTypetalkToken(userID, token)

		if err != nil {
			printError("Cannot update typetalk tokens", err)
			http.Error(w, "", http.StatusInternalServerError)
			return nil
		}

		result.IsConnected = true

		return result
	}()

	if res == nil {
		return
	}

	js, _ := json.Marshal(res)

	w.Write(js)
}

func (h *handlers) TypetalkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	token, err := h.typetalkAuth.Token(state, r)

	// if some error happen in this process, it redirects to top page without cookie.
	if err != nil {
		printError("Cannot convert to success data. maybe an error happens.", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Get profile info to retreive typetalk user id
	profile, err := h.getProfileTypetalk(token)

	if err != nil {
		printError("Cannot get my profile", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	userID, err := h.store.SaveTypetalkAccount(profile.Account.ID, token)

	if err != nil {
		printError("Cannot insert/update user's typetalk info", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := jwtToken.SignedString([]byte(h.jwtSecret))
	if err != nil {
		http.Error(w, "Cannot create token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	cookie := &http.Cookie{
		Name:     sessionName,
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handlers) getProfileTypetalk(token *oauth2.Token) (*v1.MyProfile, error) {
	client := h.typetalkAuth.NewClient(token)

	profile, _, err := client.Accounts.GetMyProfile(context.Background())

	return profile, err

}

func (h *handlers) SpotifyCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	userID := ForContext(r.Context())

	// This endpoint allows only loginned users
	if userID == 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	// Get token by code
	token, err := h.spotifyAuth.Exchange(code)

	if err != nil {
		printError("Cannot get spotify token", err)
		http.Error(w, "Cannot get token", http.StatusNotFound)
		return
	}

	// Set spotify's api token
	err = h.store.UpdateSpotifyToken(userID, token)

	if err != nil {
		printError("Cannot set spotify token to DB", err)
		http.Error(w, "Cannot set token", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handlers) StartSubscribe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ForContext(ctx)

	// This endpoint allows only loginned users
	if userID == 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	spotifyToken, err := h.store.GetSpotifyToken(userID)
	typetalkToken, err := h.store.GetTypetalkToken(userID)

	// something wrong
	if err != nil {
		http.Error(w, "Cannot get access_tokens", http.StatusInternalServerError)
		return
	}

	// it stops first, to prevent duplicate to launch polling job
	if res, ok := activeUser[userID]; ok {
		go res.StopStreaming()
		delete(activeUser, userID)
	}

	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: typetalkToken.AccessToken},
	))

	client := typetalk.NewClient(tc)
	organizations, _, err := client.Organizations.GetMyOrganizations(context.Background(), true)

	if err != nil {
		http.Error(w, "Cannot get access_tokens", http.StatusInternalServerError)
		return
	}

	spaceKeys := make([]string, len(organizations))
	for i, _ := range organizations {
		spaceKeys[i] = organizations[i].Space.Key
	}

	sc := h.spotifyAuth.NewClient(spotifyToken)

	sps := Stream{
		Conn:     &sc,
		Interval: 2 * time.Minute,
		Handler: &SpotifyStreamHandler{
			tc:        client,
			spaceKeys: spaceKeys,
			emoji:     ":musical_note:",
		},
		LoggerFunc: printError,
		ReNewClient: func(userID UserID) func() (*spotify.Client, error) {
			return func() (*spotify.Client, error) {
				token, err := h.updateSpotifyNewToken(userID)

				if err != nil {
					return nil, err
				}

				sc := h.spotifyAuth.NewClient(token)

				return &sc, nil
			}
		}(userID),
	}

	go func() {
		printInfo("start to subscribe spotify playing stream")
		err := sps.Subscribe()
		if err != nil {
			printError(err)
		}
	}()
	activeUser[userID] = sps
}

func (h *handlers) updateSpotifyNewToken(userID UserID) (*oauth2.Token, error) {
	token, err := h.store.GetSpotifyToken(userID)

	if err != nil {
		printError("Cannot get spotify token", err)
		return nil, err
	}

	if token == nil {
		return nil, nil
	}

	sc := h.spotifyAuth.NewClient(token)
	newToken, err := sc.Token()

	err = h.store.UpdateSpotifyToken(userID, newToken)

	if err != nil {
		printError("Cannot update spotify token", err)
		return nil, err
	}

	return newToken, nil
}
