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
	"github.com/nulab/go-typetalk/typetalk/shared"
	typetalk "github.com/nulab/go-typetalk/v3/typetalk/v1"
	"github.com/zmb3/spotify"
	"golang.org/x/oauth2"
)

var (
	sessionName = "session-token"
	state       = ""
	activeUser  = map[int]IStream{}
)

type handlers struct {
	typetalkAuth TypetalkAuthenticator
	spotifyAuth  SpotifyAuthenticator
	generator    Generator
	jwtSecret    string
	store        IStore
}

type TypetalkAuthenticator interface {
	NewClient(token *oauth2.Token) *typetalk.Client
	Token(state string, r *http.Request) (*oauth2.Token, error)
	AuthURL(state string) string
	RenewToken(token *oauth2.Token) (*oauth2.Token, error)
}

type SpotifyAuthenticator interface {
	Exchange(code string) (*oauth2.Token, error)
	AuthURL(state string) string
	NewClient(token *oauth2.Token) spotify.Client
}

type Generator struct {
	NewSpotifyClient  func(token *oauth2.Token, sa SpotifyAuthenticator) SpotifyAPIClient
	NewTypetalkClient func(token *oauth2.Token, ta TypetalkAuthenticator) TypetalkAPIClient
	NewSpotifyStream  func(userID UserID, spotifyClient SpotifyAPIClient, interval time.Duration, typetalkClient TypetalkAPIClient, spaceKeys []string, renewSpotifyClient func() (SpotifyAPIClient, error), renewTypetalkClient func() (TypetalkAPIClient, error)) IStream
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

type TypetalkAPIClient interface {
	GetMyOrganizations(ctx context.Context, excludesGuest bool) ([]*typetalk.Organization, *shared.Response, error)
	GetProfileTypetalk(token *oauth2.Token) (*MyProfile, error)
	SaveUserStatus(ctx context.Context, spaceKey, emoji string, opt *typetalk.SaveUserStatusOptions) (*typetalk.SaveUserStatusResult, *shared.Response, error)
	PostMessage(ctx context.Context, topicID int, message string, opt *typetalk.PostMessageOptions) (*typetalk.PostedMessageResult, *shared.Response, error)
}

type SpotifyAPIClient interface {
	Token() (*oauth2.Token, error)
	PlayerCurrentlyPlaying() (*spotify.CurrentlyPlaying, error)
}

type IStream interface {
	Subscribe() error
	Shutdown(ctx context.Context) error
}

func NewHandlers(typetalkAuth TypetalkAuthenticator, spotifyAuth SpotifyAuthenticator, generator Generator, jwtSecret string, store IStore) handlers {
	return handlers{typetalkAuth, spotifyAuth, generator, jwtSecret, store}
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

	res, err := func() (struct {
		IsConnected bool   `json:"isConnected"`
		AuthURL     string `json:"authURL"`
	}, error) {
		result := struct {
			IsConnected bool   `json:"isConnected"`
			AuthURL     string `json:"authURL"`
		}{
			AuthURL: h.spotifyAuth.AuthURL(state),
		}
		// if there is not Credentials, it returns false
		if token == nil {
			return result, nil
		}
		// Update access token every time to prevent access token is expired
		// RefreshToken of spotify won't be expired in certain term
		// sc := h.spotifyAuth.NewClient(token)
		sc := h.generator.NewSpotifyClient(token, h.spotifyAuth)

		newToken, err := sc.Token()

		if err != nil {
			return result, err
		}

		err = h.store.UpdateSpotifyToken(userID, newToken)

		if err != nil {
			return result, err
		}

		result.IsConnected = true

		return result, nil
	}()
	if err != nil {
		printError(err)
	}
	js, _ := json.Marshal(res)

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
	profile, err := h.generator.NewTypetalkClient(token, h.typetalkAuth).GetProfileTypetalk(token)

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

	// something wrong
	if err != nil {
		http.Error(w, "Cannot get spotify's access_tokens", http.StatusInternalServerError)
		return
	}
	typetalkToken, err := h.store.GetTypetalkToken(userID)

	// something wrong
	if err != nil {
		http.Error(w, "Cannot get typetalk's access_tokens", http.StatusInternalServerError)
		return
	}

	// it stops first, to prevent duplicate to launch polling job
	if res, ok := activeUser[userID]; ok {
		res.Shutdown(r.Context())
		delete(activeUser, userID)
	}

	// tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
	// 	&oauth2.Token{AccessToken: typetalkToken.AccessToken},
	// ))
	// tc

	tc := h.generator.NewTypetalkClient(typetalkToken, h.typetalkAuth)

	organizations, _, err := tc.GetMyOrganizations(context.Background(), true)

	if err != nil {
		printError(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Summarize space keys the user belongs to
	spaceKeys := make([]string, len(organizations))
	for i, _ := range organizations {
		spaceKeys[i] = organizations[i].Space.Key
	}

	// sc := h.spotifyAuth.NewClient(spotifyToken)
	sc := h.generator.NewSpotifyClient(spotifyToken, h.spotifyAuth)
	sps := h.generator.NewSpotifyStream(userID, sc, 2*time.Minute, tc, spaceKeys, func() (SpotifyAPIClient, error) {
		token, err := h.updateSpotifyNewToken(userID)

		if err != nil {
			return nil, err
		}

		sc := h.generator.NewSpotifyClient(token, h.spotifyAuth)

		return sc, nil

	}, func() (TypetalkAPIClient, error) {
		oldToken, err := h.store.GetTypetalkToken(userID)

		if err != nil {
			return nil, err
		}

		token, err := h.typetalkAuth.RenewToken(oldToken)

		if err != nil {
			printError("Refresh token is invalid", err)
			return nil, err
		}

		err = h.store.UpdateTypetalkToken(userID, token)

		if err != nil {
			printError(err)
			return nil, err
		}

		tc := h.generator.NewTypetalkClient(typetalkToken, h.typetalkAuth)

		return tc, nil
	})
	// sps := Stream{
	// 	Conn:     convertInterfaceToSpotifyClient(sc),
	// 	Interval: 2 * time.Minute,
	// 	Handler: &SpotifyStreamHandler{
	// 		tc:        convertInterfaceToTypetalkClient(&tc),
	// 		spaceKeys: spaceKeys,
	// 		emoji:     ":musical_note:",
	// 		renewClient: func(userID UserID) func() (*typetalk.Client, error) {
	// 			return func() (*typetalk.Client, error) {
	// 				oldToken, err := h.store.GetTypetalkToken(userID)

	// 				if err != nil {
	// 					return nil, err
	// 				}

	// 				token, err := h.typetalkAuth.RenewToken(oldToken)

	// 				if err != nil {
	// 					printError("Refresh token is invalid", err)
	// 					return nil, err
	// 				}

	// 				err = h.store.UpdateTypetalkToken(userID, token)

	// 				if err != nil {
	// 					printError(err)
	// 					return nil, err
	// 				}

	// 				tc := h.generator.NewTypetalkClient(typetalkToken, h.typetalkAuth)

	// 				return convertInterfaceToTypetalkClient(&tc), nil
	// 			}
	// 		}(userID),
	// 	},
	// 	LoggerFunc: printError,
	// 	ReNewSpotifyClient: func(userID UserID) func() (*spotify.Client, error) {
	// 		return func() (*spotify.Client, error) {
	// 			token, err := h.updateSpotifyNewToken(userID)

	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			sc := h.spotifyAuth.NewClient(token)

	// 			return convertInterfaceToSpotifyClient(&sc), nil
	// 		}
	// 	}(userID),
	// }

	go func() {
		printInfo("start to subscribe spotify playing stream", userID)
		err := sps.Subscribe()
		if err != nil {
			printError(err)
		}
	}()
	activeUser[userID] = sps
}

// func convertInterfaceToSpotifyClient(inPointer interface{}) *spotify.Client {
// 	return inPointer.(*spotify.Client)
// }

// func convertInterfaceToTypetalkClient(inPointer interface{}) *typetalk.Client {
// 	return inPointer.(*typetalk.Client)
// }

func (h *handlers) updateSpotifyNewToken(userID UserID) (*oauth2.Token, error) {
	token, err := h.store.GetSpotifyToken(userID)

	if err != nil {
		printError("Cannot get spotify token", err)
		return nil, err
	}

	if token == nil {
		return nil, nil
	}

	sc := h.generator.NewSpotifyClient(token, h.spotifyAuth)
	newToken, err := sc.Token()

	err = h.store.UpdateSpotifyToken(userID, newToken)

	if err != nil {
		printError("Cannot update spotify token", err)
		return nil, err
	}

	return newToken, nil
}
