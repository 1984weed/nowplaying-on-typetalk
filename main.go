package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang-migrate/migrate"
	_ "github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	_ "github.com/mattes/migrate/source/file"

	"github.com/joho/godotenv"
	typetalk "github.com/nulab/go-typetalk/v3/typetalk/v1"
	"github.com/urfave/cli"
	"github.com/zmb3/spotify"
	"golang.org/x/oauth2"
)

var debug = false

func main() {
	err := godotenv.Load()
	if err != nil {
		printInfo("There is no .env file")
	}

	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "PORT",
			EnvVar: "PORT",
			Value:  "18080",
			Usage:  "Web app port",
		},
		cli.StringFlag{
			Name:   "TYPETALK_CLIENT_ID",
			EnvVar: "TYPETALK_CLIENT_ID",
			Value:  "",
			Usage:  "Typetalk's client id for oauth2",
		},
		cli.StringFlag{
			Name:   "TYPETALK_SECRET_KEY",
			EnvVar: "TYPETALK_SECRET_KEY",
			Value:  "",
			Usage:  "Typetalk's secret key for oauth2",
		},
		cli.StringFlag{
			Name:   "TYPETALK_REDIRECT_URL",
			EnvVar: "TYPETALK_REDIRECT_URL",
			Value:  "http://localhost:18080/callback/typetalk",
			Usage:  "Callback endpoint for typetalk's oauth2",
		},
		cli.StringFlag{
			Name:   "SPOTIFY_CLIENT_ID",
			EnvVar: "SPOTIFY_CLIENT_ID",
			Value:  "",
			Usage:  "Spotify's client id for oauth2",
		},
		cli.StringFlag{
			Name:   "SPOTIFY_SECRET_KEY",
			EnvVar: "SPOTIFY_SECRET_KEY",
			Value:  "",
			Usage:  "Spotify's secret key for oauth2",
		},
		cli.StringFlag{
			Name:   "SPOTIFY_REDIRECT_URL",
			EnvVar: "SPOTIFY_REDIRECT_URL",
			Value:  "http://localhost:18080/callback/spotify",
			Usage:  "Callback endpoint for typetalk's oauth2",
		},
		cli.StringFlag{
			Name:   "DATABASE_URL",
			EnvVar: "DATABASE_URL",
			Value:  "postgres://postgres:postgres@localhost:5432/nowonplaying?sslmode=disable",
			Usage:  "DB user",
		},
		cli.StringFlag{
			Name:   "JWT_SECRET",
			EnvVar: "JWT_SECRET",
			Value:  "secret",
			Usage:  "The secret of JWT",
		},
	}

	app.Action = func(ctx *cli.Context) error {
		// Update to the latest database state
		m, err := migrate.New(
			"file://./db/migration",
			ctx.String("DATABASE_URL"))

		if err != nil {
			printFatal(err)
		}

		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			printFatal(err)
		}

		db, err := sql.Open("postgres", ctx.String("DATABASE_URL"))

		if err != nil {
			printFatal(err, "Cannot connect to postgesql. it didn't launch")
			return err
		}

		typetalkAuth := NewAuthenticator(ctx.String("TYPETALK_CLIENT_ID"), ctx.String("TYPETALK_SECRET_KEY"), ctx.String("TYPETALK_REDIRECT_URL"), "my")

		spotifyAuth := spotify.NewAuthenticator(ctx.String("SPOTIFY_REDIRECT_URL"), spotify.ScopeUserReadCurrentlyPlaying)
		spotifyAuth.SetAuthInfo(ctx.String("SPOTIFY_CLIENT_ID"), ctx.String("SPOTIFY_SECRET_KEY"))

		store := NewStore(db)
		handlers := NewHandlers(typetalkAuth, spotifyAuth, ctx.String("JWT_SECRET"), &store)

		authMid := authMiddleware(ctx.String("JWT_SECRET"))

		http.HandleFunc("/", authMid(http.HandlerFunc(handlers.Top)))
		// Typetalk callback
		http.HandleFunc("/callback/typetalk", handlers.TypetalkCallbackHandler)
		// Spotify callback
		http.HandleFunc("/callback/spotify", authMid(http.HandlerFunc(handlers.SpotifyCallbackHandler)))

		// Start subscribe spotify stream
		http.HandleFunc("/subscribe/start", authMid(http.HandlerFunc(handlers.StartSubscribe)))

		http.HandleFunc("/ping/spotify", authMid(http.HandlerFunc(handlers.CheckConnectionSpotify)))
		http.HandleFunc("/ping/typetalk", authMid(http.HandlerFunc(handlers.CheckConnectionTypetalk)))

		port := ctx.String("PORT")
		printInfo("Server is running on", fmt.Sprintf("http://localhost:%s", port))
		http.ListenAndServe(fmt.Sprintf(":%s", port), nil)

		return nil
	}
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

type contextKey struct {
	name string
}

// context key for user id
var userCtxKey = &contextKey{"user"}

// Middleware decodes the share session cookie and packs the session into context
func authMiddleware(jwtSecret string) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session-token")

			// when cookie is empty, it replaces to empty cookie
			if err == http.ErrNoCookie {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := cookie.Value
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(jwtSecret), nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				// put it in context
				ctx := context.WithValue(r.Context(), userCtxKey, claims["user_id"])

				// and call the next with our new context
				r = r.WithContext(ctx)
			} else {
				cookie := &http.Cookie{
					Name:    sessionName,
					Value:   "",
					Path:    "/",
					Expires: time.Unix(0, 0),
				}
				http.SetCookie(w, cookie)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func ForContext(ctx context.Context) int {
	raw, _ := ctx.Value(userCtxKey).(float64)
	return int(raw)
}

func saveSpotifyTokenToFile(dir string, token *oauth2.Token) error {
	blob, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(dir, "spotify"), blob, 0644)
}

func newSpotify(auth *spotify.Authenticator, token *oauth2.Token) (*spotify.Client, error) {
	c := auth.NewClient(token)
	c.AutoRetry = true
	user, err := c.CurrentUser()
	if err != nil {
		return nil, err
	}
	// use the sc to make calls that require authorization
	printDebug("You are logged in as:", user.ID)
	return &c, nil
}

type SpotifyStreamHandler struct {
	tc        *typetalk.Client
	emoji     string
	spaceKeys []string
	topics    []int
}

func (h *SpotifyStreamHandler) Serve(playing *spotify.CurrentlyPlaying) {
	if len(h.topics) > 0 {
		for _, topicID := range h.topics {
			h.postTopic(topicID, playing)
		}
	}
	// eg. https://open.spotify.com/track/6aOaB0vl2ilHxRb23Wiazv
	externalURL := playing.Item.ExternalURLs["spotify"]
	// eg. Retarded/KID FRESINO
	metadata := generateMetadata(playing, &metadataOption{trackInfo: true, albumName: false, albumImage: false, short: true})
	if 25 < utf8.RuneCountInString(metadata) {
		metadata = string([]rune(metadata)[:25]) + "…"
	}
	// eg. Retarded/KID FRESINO https://open.spotify.com/track/6aOaB0vl2ilHxRb23Wiazv
	msg := fmt.Sprintf("%s %s", metadata, externalURL)
	printDebug("NOW PLAYING", "-", msg)

	for _, v := range h.spaceKeys {
		_, _, err := h.tc.Statuses.SaveUserStatus(context.Background(),
			v, ":musical_note:", &typetalk.SaveUserStatusOptions{
				Message:                msg,
				ClearAt:                "",
				IsNotificationDisabled: false,
			})
		if err != nil {
			printError(err)
		}

	}
}

func (h *SpotifyStreamHandler) postTopic(topicID int, playing *spotify.CurrentlyPlaying) {
	// eg. https://open.spotify.com/track/6aOaB0vl2ilHxRb23Wiazv
	externalURL := playing.Item.ExternalURLs["spotify"]
	// eg. Retarded/KID FRESINO - ai qing [ ](https://i.scdn.co/image/ab67616d0000b273b3ca13afd5b1315924854ce7)
	metadata := generateMetadata(playing, &metadataOption{trackInfo: true, albumName: true, albumImage: true, short: false})
	msg := fmt.Sprintf("%s %s\n%s", h.emoji, metadata, externalURL)
	_, _, err := h.tc.Messages.PostMessage(context.Background(), topicID, msg, &typetalk.PostMessageOptions{})
	if err != nil {
		printError(err)
	}
}

type metadataOption struct {
	trackInfo  bool
	albumName  bool
	albumImage bool
	short      bool
}

func generateMetadata(playing *spotify.CurrentlyPlaying, opt *metadataOption) string {
	meta := ""
	if opt.trackInfo {
		// eg. Retarded
		trackName := playing.Item.Name
		// eg. KID FRESINO
		artistName := playing.Item.Artists[0].Name
		format := "%s / %s"
		if opt.short {
			format = "%s/%s"
		}
		meta += fmt.Sprintf(format, trackName, artistName)
	}
	if opt.albumName {
		albumName := playing.Item.Album.Name
		meta += fmt.Sprintf(" - %s", albumName)
	}
	if opt.albumImage {
		albumImageURL := playing.Item.Album.Images[0].URL
		meta += fmt.Sprintf(" [ ](%s)", albumImageURL)
	}
	return meta
}

func printDebug(args ...interface{}) {
	if debug {
		args = append([]interface{}{"[DEBUG]"}, args...)
		log.Println(args...)
	}
}

func printInfo(args ...interface{}) {
	args = append([]interface{}{"[INFO]"}, args...)
	log.Println(args...)
}

func printError(args ...interface{}) {
	args = append([]interface{}{"[ERROR]"}, args...)
	log.Println(args...)
}

func printFatal(args ...interface{}) {
	args = append([]interface{}{"[FATAL]"}, args...)
	log.Fatalln(args...)
}
