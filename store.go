package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

type UserID = int
type store struct {
	db *sql.DB
}

const (
	spotifyProvider  = "spotify"
	typetalkProvider = "typetalk"
)

type IStore interface {
	SaveTypetalkAccount(typetalkAccountID int, token *oauth2.Token) (UserID, error)
	GetTypetalkToken(userID UserID) (*oauth2.Token, error)
	UpdateTypetalkToken(userID UserID, token *oauth2.Token) error
	UpdateSpotifyToken(userID UserID, token *oauth2.Token) error
	GetSpotifyToken(userID UserID) (*oauth2.Token, error)
}

func NewStore(db *sql.DB) store {
	return store{db}
}

func (s *store) SaveTypetalkAccount(typetalkAccountID int, token *oauth2.Token) (UserID, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		printError(err)
		return 0, err
	}

	var userID UserID
	err = tx.QueryRow(`INSERT INTO users (typetalk_user_id) VALUES($1)
	ON CONFLICT (typetalk_user_id)
	DO  UPDATE SET typetalk_user_id=EXCLUDED.typetalk_user_id returning id`, typetalkAccountID).Scan(&userID)

	if err != nil {
		tx.Rollback()
		printError("An error happened while create/update users", err)
		return 0, err
	}

	_, err = tx.Exec(`INSERT INTO oauth2 (user_id, access_token, refresh_token, expire_time, provider) VALUES($1,$2,$3,$4,'typetalk')
		ON CONFLICT (user_id, provider)
		DO
		UPDATE SET (access_token, refresh_token, expire_time) = ($2,$3,$4)`, userID, token.AccessToken, token.RefreshToken, token.Expiry)

	if err != nil {
		tx.Rollback()
		printError("An error happened while create/update oauth2", err)
		return 0, err
	}
	err = tx.Commit()

	if err != nil {
		printError(err)
		return 0, err
	}

	return userID, nil
}

func (s *store) GetTypetalkToken(userID UserID) (*oauth2.Token, error) {
	return s.getOauthTokenByProvider(userID, typetalkProvider)
}

func (s *store) UpdateTypetalkToken(userID UserID, token *oauth2.Token) error {
	return s.updateTokenByProvider(userID, token, typetalkProvider)
}

func (s *store) UpdateSpotifyToken(userID UserID, token *oauth2.Token) error {
	return s.updateTokenByProvider(userID, token, spotifyProvider)
}

func (s *store) updateTokenByProvider(userID UserID, token *oauth2.Token, provider string) error {
	_, err := s.db.Exec(`INSERT INTO oauth2 (user_id, access_token, refresh_token, expire_time, provider) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (user_id, provider)
		DO
		UPDATE SET (access_token, refresh_token, expire_time) = ($2,$3,$4)`, userID, token.AccessToken, token.RefreshToken, token.Expiry, provider)

	if err != nil {
		printError(fmt.Sprintf("Cannot update oauth2 of %s", provider), err)
		return err
	}
	return nil
}

func (s *store) GetSpotifyToken(userID UserID) (*oauth2.Token, error) {
	return s.getOauthTokenByProvider(userID, "spotify")
}

func (s *store) getOauthTokenByProvider(userID UserID, provider string) (*oauth2.Token, error) {
	var (
		typetalkAccessToken  string
		typetalkRefreshToken string
		expireTime           time.Time
	)
	err := s.db.QueryRow(`SELECT oauth2.access_token, oauth2.refresh_token, oauth2.expire_time
	FROM oauth2, users
	WHERE users.id = $1 
	AND oauth2.provider = $2
	AND oauth2.user_id = users.id`, userID, provider).Scan(&typetalkAccessToken, &typetalkRefreshToken, &expireTime)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		printError(fmt.Sprintf("Cannot retrieve access token / refresh token of %s", provider), err)
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  typetalkAccessToken,
		RefreshToken: typetalkRefreshToken,
		Expiry:       expireTime,
	}, nil
}
