package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nulab/go-typetalk/typetalk/shared"
	typetalk "github.com/nulab/go-typetalk/v3/typetalk/v1"
	"github.com/zmb3/spotify"
	"golang.org/x/oauth2"
)

const jwtSecret = "secret"

var testTypetalkCredential = &Oauth2Credential{
	ClientID:    "typetalkClientID",
	SecretKey:   "typetalkSecretKey",
	RedirectURI: "typetalkRedirectURI",
	Scope:       "my",
}

var testSpotifyCredential = &Oauth2Credential{
	ClientID:    "typetalkClientID",
	SecretKey:   "typetalkSecretKey",
	RedirectURI: "typetalkRedirectURI",
	Scope:       "my",
}

func newHandler(typetalkAuthMock TypetalkAuthenticator, spotifyAuthenticatorMock SpotifyAuthenticator, generator Generator, storeMock IStore) handlers {
	return NewHandlers(typetalkAuthMock, spotifyAuthenticatorMock, generator, "secret", storeMock)
}

func TestTopShouldReturnNotLoginPage(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	wantAuthURL := "https://typetalk.com/oauth2/authorize?client_id=typetalkClientID&redirect_uri=typetalkRedirectURI&scope=my&response_type=code"
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handlerInstance := newHandler(TypetalkAuthenticatorMock{
		AuthURLFunc: func(state string) string {
			return wantAuthURL
		},
	}, &SpotifyAuthenticatorMock{}, Generator{}, StoreMock{})
	handler := http.HandlerFunc(handlerInstance.Top)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	want := getIndexHTML(wantAuthURL)

	if rr.Body.String() != want {
		t.Errorf("Handler returned wrong html: got %v want %v",
			rr.Body.String(), want)
	}
}

func TestTopShouldReturnLoginedPage(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handlerInstance := newHandler(TypetalkAuthenticatorMock{}, &SpotifyAuthenticatorMock{}, Generator{}, StoreMock{})

	// Set userID for loging users
	ctx := req.Context()
	ctx = context.WithValue(ctx, userCtxKey, float64(1))

	handler := http.HandlerFunc(handlerInstance.Top)

	req = req.WithContext(ctx)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	want := getLoginnedIndexHTML()

	if rr.Body.String() != want {
		t.Errorf("Handler returned wrong html: got %v want %v",
			rr.Body.String(), want)
	}
}

func TestTypetalkCallback(t *testing.T) {
	req, err := http.NewRequest("GET", "/callback/typetalk", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantTypetalID := 2488
	wantToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}
	userID := 1
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, _ := jwtToken.SignedString([]byte(jwtSecret))

	// Set cookie
	cookie := &http.Cookie{
		Name:     sessionName,
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
	}

	cases := []struct {
		name              string
		newTypetalkClient TypetalkAPIClient
		saveTypetalkFunc  func(typetalkAccountID int, token *oauth2.Token) (UserID, error)
		wantStatus        int
		wantCookie        string
	}{
		{
			name: "No failures",
			newTypetalkClient: &TypetalkAPIClientMock{
				GetProfileTypetalkFunc: func(token *oauth2.Token) (*MyProfile, error) {
					return &MyProfile{
						&typetalk.Account{ID: wantTypetalID},
					}, nil
				},
			},
			saveTypetalkFunc: func(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
				if typetalkAccountID != wantTypetalID {
					t.Error("Update db with wrong typetalk ID")
				}
				return userID, nil
			},
			wantStatus: http.StatusSeeOther,
			wantCookie: cookie.String(),
		},
		{
			name: "Profile request failed",
			newTypetalkClient: &TypetalkAPIClientMock{
				GetProfileTypetalkFunc: func(token *oauth2.Token) (*MyProfile, error) {
					return nil, errors.New("permission denied")
				},
			},
			saveTypetalkFunc: func(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
				if typetalkAccountID != wantTypetalID {
					t.Error("Update db with wrong typetalk ID")
				}
				return userID, nil
			},
			wantStatus: http.StatusInternalServerError,
			wantCookie: "",
		},
		{
			name: "Update token failed",
			newTypetalkClient: &TypetalkAPIClientMock{
				GetProfileTypetalkFunc: func(token *oauth2.Token) (*MyProfile, error) {
					return &MyProfile{
						&typetalk.Account{ID: wantTypetalID},
					}, nil
				},
			},
			saveTypetalkFunc: func(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
				return 0, fmt.Errorf("An error happens")
			},
			wantStatus: http.StatusInternalServerError,
			wantCookie: "",
		},
	}

	for _, c := range cases {
		handlerInstance := newHandler(TypetalkAuthenticatorMock{
			TokenFunc: func(state string, r *http.Request) (*oauth2.Token, error) {
				return wantToken, nil
			},
		}, &SpotifyAuthenticatorMock{}, Generator{
			NewTypetalkClient: func(token *oauth2.Token, sa TypetalkAuthenticator) TypetalkAPIClient {
				return c.newTypetalkClient
			}}, StoreMock{
			SaveTypetalkAccountFunc: func(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
				return c.saveTypetalkFunc(typetalkAccountID, token)
			},
		})
		handler := http.HandlerFunc(handlerInstance.TypetalkCallbackHandler)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		res := rr.Result()

		if c.wantCookie != "" && c.wantCookie != res.Header.Get("Set-Cookie") {
			t.Errorf("%s: Handler returned wrong set-cookie: got %v want %v",
				c.name, res.Header.Get("Set-Cookie"), cookie.String())
		}

		if status := rr.Code; status != c.wantStatus {
			t.Errorf("%s: Handler returned wrong status code: got %v want %v",
				c.name, status, c.wantStatus)
		}
	}
}

func TestSpotifyCallbackHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/callback/spotify", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}
	cases := []struct {
		name                   string
		exchangeFunc           func(code string) (*oauth2.Token, error)
		updateSpotifyTokenFunc func(userID UserID, token *oauth2.Token) error
		userID                 int
		wantStatus             int
	}{
		{
			name: "should return 301 status",
			exchangeFunc: func(code string) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				if token != wantToken {
					t.Errorf("Token is invalid, got: %v, want: %v", token, wantToken)
				}
				return nil
			},
			userID:     1,
			wantStatus: http.StatusSeeOther,
		},
		{
			name: "should return 404 status",
			exchangeFunc: func(code string) (*oauth2.Token, error) {
				return nil, fmt.Errorf("An error happens")
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return nil
			},
			userID:     1,
			wantStatus: http.StatusNotFound,
		},
		{
			name: "should return 500 status",
			exchangeFunc: func(code string) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				if token != wantToken {
					t.Errorf("Token is invalid, got: %v, want: %v", token, wantToken)
				}
				return fmt.Errorf("An error happens on DB")
			},
			userID:     1,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "should return 403 status",
			exchangeFunc: func(code string) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				if token != wantToken {
					t.Errorf("Token is invalid, got: %v, want: %v", token, wantToken)
				}
				return nil
			},
			userID:     0,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, c := range cases {
		handlerInstance := newHandler(TypetalkAuthenticatorMock{}, &SpotifyAuthenticatorMock{
			ExchangeFunc: c.exchangeFunc,
		}, Generator{}, StoreMock{
			UpdateSpotifyTokenFunc: c.updateSpotifyTokenFunc,
		})

		// This callback shouldn't allow to guest users
		ctx := req.Context()
		ctx = context.WithValue(ctx, userCtxKey, float64(c.userID))

		handler := http.HandlerFunc(handlerInstance.SpotifyCallbackHandler)

		rr := httptest.NewRecorder()

		req = req.WithContext(ctx)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != c.wantStatus {
			t.Errorf("%s: Handler returned wrong status code: got %v want %v",
				c.name, status, c.wantStatus)
		}
	}
}

func TestCheckConnectionTypetalkHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/ping/typetalk", nil)
	if err != nil {
		t.Fatal(err)
	}

	wantToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	renewedToken := &oauth2.Token{
		AccessToken:  "RENEWED_ACCESS_TOKEN",
		RefreshToken: "RENEWED_REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	wantAuthURL := AuthURL

	cases := []struct {
		name                    string
		renewTokenFunc          func(token *oauth2.Token) (*oauth2.Token, error)
		getTypetalkTokenFunc    func(userID UserID) (*oauth2.Token, error)
		updateTypetalkTokenFunc func(userID UserID, token *oauth2.Token) error
		userID                  int
		wantStatus              int
		wantIsConnect           bool
	}{
		{
			name: "Should return 200 and isconnected true",
			renewTokenFunc: func(token *oauth2.Token) (*oauth2.Token, error) {
				return renewedToken, nil
			},
			getTypetalkTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateTypetalkTokenFunc: func(userID UserID, token *oauth2.Token) error {
				if token != renewedToken {
					t.Errorf("Token is invalid, got: %v, want: %v", token, renewedToken)
				}
				return nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: true,
		},
		{
			name: "Should return 200 and isconnected false",
			renewTokenFunc: func(token *oauth2.Token) (*oauth2.Token, error) {
				return renewedToken, nil
			},
			getTypetalkTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return nil, nil
			},
			updateTypetalkTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
		{
			name: "Should return 200 and isconnected false because of a failure of renew token",
			renewTokenFunc: func(token *oauth2.Token) (*oauth2.Token, error) {
				return nil, errors.New("Failed to get renew token")
			},
			getTypetalkTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateTypetalkTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
		{
			name: "Should return 500",
			renewTokenFunc: func(token *oauth2.Token) (*oauth2.Token, error) {
				return renewedToken, nil
			},
			getTypetalkTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateTypetalkTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return errors.New("Failed to update DB")
			},
			userID:     1,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "Should return 403",
			userID:     0,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, c := range cases {
		// RenewToken
		handlerInstance := newHandler(TypetalkAuthenticatorMock{
			RenewTokenFunc: c.renewTokenFunc,
			AuthURLFunc: func(state string) string {
				return wantAuthURL
			},
		}, &SpotifyAuthenticatorMock{}, Generator{}, StoreMock{
			GetTypetalkTokenFunc:    c.getTypetalkTokenFunc,
			UpdateTypetalkTokenFunc: c.updateTypetalkTokenFunc,
		})
		handler := http.HandlerFunc(handlerInstance.CheckConnectionTypetalk)

		ctx := req.Context()
		ctx = context.WithValue(ctx, userCtxKey, float64(c.userID))
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != c.wantStatus {
			t.Errorf("%s: Handler returned wrong status code: got %v want %v",
				c.name, status, c.wantStatus)
		}
		if c.wantStatus != http.StatusOK {
			continue
		}
		wantBody := fmt.Sprintf(`{"isConnected":%v,"authURL":"%s"}`, c.wantIsConnect, wantAuthURL)

		if rr.Body.String() != wantBody {
			t.Errorf("%s: Handler returned wrong body: got %v want %v",
				c.name, rr.Body.String(), wantBody)
		}
	}
}

func TestCheckConnectionSpotifyHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/ping/spotify", nil)
	if err != nil {
		t.Fatal(err)
	}

	wantToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	renewedToken := &oauth2.Token{
		AccessToken:  "RENEWED_ACCESS_TOKEN",
		RefreshToken: "RENEWED_REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	wantAuthURL := spotify.AuthURL

	cases := []struct {
		name                   string
		tokenFunc              func() (*oauth2.Token, error)
		getSpotifyTokenFunc    func(userID UserID) (*oauth2.Token, error)
		updateSpotifyTokenFunc func(userID UserID, token *oauth2.Token) error
		userID                 int
		wantStatus             int
		wantIsConnect          bool
	}{
		{
			name: "Should return 200 with auth url",
			tokenFunc: func() (*oauth2.Token, error) {
				return renewedToken, nil
			},
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: true,
		},
		{
			name:       "Should return 403 because users are not loginned",
			userID:     0,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Should return 500 because an error happened when get token",
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return nil, errors.New("cannot get token")
			},
			userID:     1,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "Should return 200 and json not connected because token is not set",
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return nil, nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
		{
			name: "Should return 200 and json not connected because token is not set",
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return nil, nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
		{
			name: "Should return 200 and isconnected false because of a failure of renew token",
			tokenFunc: func() (*oauth2.Token, error) {
				return nil, errors.New("an error happened when get a new token using the refresh token")
			},
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return nil
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
		{
			name: "Should return 200 and isconnected false because of a failure of update token",
			tokenFunc: func() (*oauth2.Token, error) {
				return renewedToken, nil
			},
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantToken, nil
			},
			updateSpotifyTokenFunc: func(userID UserID, token *oauth2.Token) error {
				return errors.New("an error happend when updating token")
			},
			userID:        1,
			wantStatus:    http.StatusOK,
			wantIsConnect: false,
		},
	}

	for _, c := range cases {
		handlerInstance := newHandler(TypetalkAuthenticatorMock{}, &SpotifyAuthenticatorMock{
			AuthURLFunc: func(state string) string {
				return wantAuthURL
			},
		}, Generator{
			NewSpotifyClient: func(token *oauth2.Token, sa SpotifyAuthenticator) SpotifyAPIClient {
				return &SpotifyAPIClientMock{
					TokenFunc: c.tokenFunc,
				}
			},
		}, StoreMock{
			GetSpotifyTokenFunc:    c.getSpotifyTokenFunc,
			UpdateSpotifyTokenFunc: c.updateSpotifyTokenFunc,
		})
		handler := http.HandlerFunc(handlerInstance.CheckConnectionSpotify)

		ctx := req.Context()
		ctx = context.WithValue(ctx, userCtxKey, float64(c.userID))
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != c.wantStatus {
			t.Errorf("%s: Handler returned wrong status code: got %v want %v",
				c.name, status, c.wantStatus)
		}
		if c.wantStatus != http.StatusOK {
			continue
		}
		wantBody := fmt.Sprintf(`{"isConnected":%v,"authURL":"%s"}`, c.wantIsConnect, wantAuthURL)

		if rr.Body.String() != wantBody {
			t.Errorf("%s: Handler returned wrong body: got %v want %v",
				c.name, rr.Body.String(), wantBody)
		}
	}
}

func TestStartStartSubscribe(t *testing.T) {
	req, err := http.NewRequest("GET", "/subscribe/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantSpotifyToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}
	wantTypetalkToken := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}
	cases := []struct {
		name                string
		getMyOrganizations  func(ctx context.Context, excludesGuest bool) ([]*typetalk.Organization, *shared.Response, error)
		getSpotifyTokenFunc func(userID UserID) (*oauth2.Token, error)
		getTypetalkFunc     func(userID UserID) (*oauth2.Token, error)
		userID              int
		wantStatus          int
	}{
		{
			name: "Should return 200",
			getMyOrganizations: func(ctx context.Context, excludesGuest bool) ([]*typetalk.Organization, *shared.Response, error) {
				return []*typetalk.Organization{
					{
						Space: &typetalk.Space{
							Key: "test1",
						},
					},
				}, nil, nil
			},
			getSpotifyTokenFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantSpotifyToken, nil
			},
			getTypetalkFunc: func(userID UserID) (*oauth2.Token, error) {
				return wantTypetalkToken, nil
			},
			userID:     1,
			wantStatus: http.StatusOK,
		},
	}

	for _, c := range cases {
		handlerInstance := newHandler(TypetalkAuthenticatorMock{}, &SpotifyAuthenticatorMock{}, Generator{
			NewTypetalkClient: func(token *oauth2.Token, ta TypetalkAuthenticator) TypetalkAPIClient {
				return &TypetalkAPIClientMock{
					GetMyOrganizationsFunc: c.getMyOrganizations,
				}
			},
			NewSpotifyClient: func(token *oauth2.Token, sa SpotifyAuthenticator) SpotifyAPIClient {
				return &SpotifyAPIClientMock{}
			},
			NewSpotifyStream: func(userID UserID, spotifyClient SpotifyAPIClient, interval time.Duration, typetalkClient TypetalkAPIClient, spaceKeys []string, renewSpotifyClient func() (SpotifyAPIClient, error), renewTypetalkClient func() (TypetalkAPIClient, error)) IStream {
				return &StreamMock{
					SubscribeFunc: func() error {
						return nil
					},
				}
			},
		}, StoreMock{
			GetTypetalkTokenFunc: c.getTypetalkFunc,
			GetSpotifyTokenFunc:  c.getSpotifyTokenFunc,
		})
		handler := http.HandlerFunc(handlerInstance.StartSubscribe)
		ctx := req.Context()
		ctx = context.WithValue(ctx, userCtxKey, float64(c.userID))
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != c.wantStatus {
			t.Errorf("%s: Handler returned wrong status code: got %v want %v",
				c.name, status, c.wantStatus)
		}
	}
}
func getLoginnedIndexHTML() string {
	dat, _ := ioutil.ReadFile("./index-user-page.html")
	datStr := string(dat)

	return datStr
}

func getIndexHTML(authURL string) string {
	dat, _ := ioutil.ReadFile("./index.html")
	datStr := string(dat)

	r := strings.NewReplacer("{{.AuthURL}}", authURL)

	return r.Replace(datStr)
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

type TypetalkAuthenticatorMock struct {
	TokenFunc      func(state string, r *http.Request) (*oauth2.Token, error)
	AuthURLFunc    func(state string) string
	NewClientFunc  func(token *oauth2.Token) *typetalk.Client
	RenewTokenFunc func(token *oauth2.Token) (*oauth2.Token, error)
}

func (a TypetalkAuthenticatorMock) Token(state string, r *http.Request) (*oauth2.Token, error) {
	if a.TokenFunc == nil {
		return nil, errors.New("Token not found")
	}
	return a.TokenFunc(state, r)
}

func (a TypetalkAuthenticatorMock) AuthURL(state string) string {
	if a.AuthURLFunc == nil {
		return ""
	}
	return a.AuthURLFunc(state)
}
func (a TypetalkAuthenticatorMock) NewClient(token *oauth2.Token) *typetalk.Client {
	if a.NewClientFunc == nil {
		return nil
	}
	return a.NewClientFunc(token)
}
func (a TypetalkAuthenticatorMock) RenewToken(token *oauth2.Token) (*oauth2.Token, error) {
	if a.RenewTokenFunc == nil {
		return nil, errors.New("Token not found")
	}
	return a.RenewTokenFunc(token)
}

type SpotifyAuthenticatorMock struct {
	AuthURLFunc   func(state string) string
	NewClientFunc func(token *oauth2.Token) spotify.Client
	ExchangeFunc  func(code string) (*oauth2.Token, error)
}

func (s *SpotifyAuthenticatorMock) AuthURL(state string) string {
	if s.AuthURLFunc == nil {
		return ""
	}
	return s.AuthURLFunc(state)
}

func (s *SpotifyAuthenticatorMock) NewClient(token *oauth2.Token) spotify.Client {
	if s.NewClientFunc == nil {
		return spotify.Client{}
	}
	return s.NewClientFunc(token)
}

func (s *SpotifyAuthenticatorMock) Exchange(code string) (*oauth2.Token, error) {
	if s.ExchangeFunc == nil {
		return nil, errors.New("Token not found")
	}
	return s.ExchangeFunc(code)
}

type StoreMock struct {
	SaveTypetalkAccountFunc func(typetalkAccountID int, token *oauth2.Token) (UserID, error)
	GetTypetalkTokenFunc    func(userID UserID) (*oauth2.Token, error)
	UpdateTypetalkTokenFunc func(userID UserID, token *oauth2.Token) error
	UpdateSpotifyTokenFunc  func(userID UserID, token *oauth2.Token) error
	GetSpotifyTokenFunc     func(userID UserID) (*oauth2.Token, error)
}

func (s StoreMock) SaveTypetalkAccount(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
	return s.SaveTypetalkAccountFunc(typetalkAccountID, token)
}
func (s StoreMock) GetTypetalkToken(userID UserID) (*oauth2.Token, error) {
	return s.GetTypetalkTokenFunc(userID)
}
func (s StoreMock) UpdateTypetalkToken(userID UserID, token *oauth2.Token) error {
	return s.UpdateTypetalkTokenFunc(userID, token)
}
func (s StoreMock) UpdateSpotifyToken(userID UserID, token *oauth2.Token) error {
	return s.UpdateSpotifyTokenFunc(userID, token)
}

func (s StoreMock) GetSpotifyToken(userID UserID) (*oauth2.Token, error) {
	return s.GetSpotifyTokenFunc(userID)
}

type TypetalkAPIClientMock struct {
	GetMyOrganizationsFunc func(ctx context.Context, excludesGuest bool) ([]*typetalk.Organization, *shared.Response, error)
	GetProfileTypetalkFunc func(token *oauth2.Token) (*MyProfile, error)
}

func (t *TypetalkAPIClientMock) GetMyOrganizations(ctx context.Context, excludesGuest bool) ([]*typetalk.Organization, *shared.Response, error) {
	return t.GetMyOrganizationsFunc(ctx, excludesGuest)
}

func (t *TypetalkAPIClientMock) GetProfileTypetalk(token *oauth2.Token) (*MyProfile, error) {
	return t.GetProfileTypetalkFunc(token)
}

type SpotifyAPIClientMock struct {
	TokenFunc func() (*oauth2.Token, error)
}

func (s *SpotifyAPIClientMock) Token() (*oauth2.Token, error) {
	return s.TokenFunc()
}

type StreamMock struct {
	SubscribeFunc func() error
	ShutdownFunc  func(ctx context.Context) error
}

func (s *StreamMock) Subscribe() error {
	return s.SubscribeFunc()
}
func (s *StreamMock) Shutdown(ctx context.Context) error {
	return s.Shutdown(ctx)
}
