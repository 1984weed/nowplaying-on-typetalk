package main

import (
	"database/sql/driver"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"golang.org/x/oauth2"
)

type AnyTime struct{}

// Match satisfies sqlmock.Argument interface
func (a AnyTime) Match(v driver.Value) bool {
	_, ok := v.(time.Time)
	return ok
}

func TestShouldSaveTypetalkUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	var (
		expectUserID UserID = 2
		accessToken         = "ACCESS_TOKEN"
		refreshToken        = "REFRESH_TOKEN"
		expiry              = time.Now()
	)

	rows := sqlmock.NewRows([]string{"id"}).
		AddRow(expectUserID)
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(rows)
	mock.ExpectExec("INSERT INTO oauth2").WithArgs(2, 3).WithArgs(expectUserID, accessToken, refreshToken, expiry, AnyTime{}).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	store := NewStore(db)
	userID, err := store.SaveTypetalkAccount(102, &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
	})

	if err != nil {
		t.Errorf("SaveTypetalAccount failed")
	}

	if userID != expectUserID {
		t.Errorf("Actual UserID: %d is wrong", userID)
	}
}

func TestShouldSaveTypetalkUserOnFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	var (
		accessToken  = "ACCESS_TOKEN"
		refreshToken = "REFRESH_TOKEN"
		expiry       = time.Now()
	)

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").WillReturnError(fmt.Errorf("update users error"))
	mock.ExpectRollback()

	store := NewStore(db)
	userID, err := store.SaveTypetalkAccount(102, &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
	})

	if err == nil {
		t.Errorf("SaveTypetalAccount succeeded")
	}

	if userID != 0 {
		t.Errorf("userID should be 0")
	}
}

func TestShouldGetTypetalkToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	want := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now().UTC(),
	}

	rows := sqlmock.NewRows([]string{"access_token", "refresh_token", "expire_time"}).
		AddRow(want.AccessToken, want.RefreshToken, want.Expiry)

	userID := 1
	mock.ExpectQuery("SELECT (.+) FROM oauth2, users").WithArgs(userID, "typetalk").WillReturnRows(rows)

	store := NewStore(db)
	got, err := store.GetTypetalkToken(userID)

	if err != nil {
		t.Errorf("failed")
	}

	if got == nil {
		t.Errorf("got is nil")
	}

	if got.AccessToken != want.AccessToken {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
	if got.Expiry != TimeLocal(want.Expiry, "") {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
}

func TestShouldGetTypetalkTokenEmpty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	rows := sqlmock.NewRows([]string{"access_token", "refresh_token", "expire_time"})

	userID := 1
	mock.ExpectQuery("SELECT (.+) FROM oauth2, users").WithArgs(userID, "typetalk").WillReturnRows(rows)

	store := NewStore(db)
	got, err := store.GetTypetalkToken(userID)

	if err != nil {
		t.Errorf("failed")
	}

	if got != nil {
		t.Errorf("got is not nil")
	}
}

func TestShouldGetSpotifyToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	want := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now().UTC(),
	}

	rows := sqlmock.NewRows([]string{"access_token", "refresh_token", "expire_time"}).
		AddRow(want.AccessToken, want.RefreshToken, want.Expiry)

	userID := 1
	mock.ExpectQuery("SELECT (.+) FROM oauth2, users").WithArgs(userID, "spotify").WillReturnRows(rows)

	store := NewStore(db)
	got, err := store.GetSpotifyToken(userID)

	if err != nil {
		t.Errorf("failed")
	}

	if got == nil {
		t.Errorf("got is nil")
	}

	if got.AccessToken != want.AccessToken {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
	if got.Expiry != TimeLocal(want.Expiry, "") {
		t.Errorf("got [%v], want [%v] ", got, want)
	}
}

func TestShouldUpdateTypetalkToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	sample := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	userID := 1
	mock.ExpectExec("INSERT INTO oauth2").WithArgs(userID, sample.AccessToken, sample.RefreshToken, sample.Expiry, "typetalk", AnyTime{}).WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewStore(db)
	err = store.UpdateTypetalkToken(userID, sample)

	if err != nil {
		t.Errorf("failed")
	}
}

func TestShouldUpdateSpotifyToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	sample := &oauth2.Token{
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		Expiry:       time.Now(),
	}

	userID := 1
	mock.ExpectExec("INSERT INTO oauth2").WithArgs(userID, sample.AccessToken, sample.RefreshToken, sample.Expiry, "spotify", AnyTime{}).WillReturnResult(sqlmock.NewResult(1, 1))

	store := NewStore(db)
	err = store.UpdateSpotifyToken(userID, sample)

	if err != nil {
		t.Errorf("failed")
	}
}
