package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zmb3/spotify"
)

const (
	name            = "spotify playing stream"
	minimumInterval = time.Second
)

var (
	ErrStreamSubscribed = errors.New(name + " subscribed")
	finishCh            = make(chan int)
)

type Stream struct {
	Conn        *spotify.Client
	Handler     Handler
	Interval    time.Duration
	LoggerFunc  LoggerFunc
	ReNewClient func() (*spotify.Client, error)

	started         int32
	inShutdown      int32
	mu              sync.Mutex
	activePlaying   map[*spotify.CurrentlyPlaying]struct{}
	activePlayingWg sync.WaitGroup
	doneChan        chan struct{}
	onShutdown      []func()
}

func (s *Stream) Subscribe() error {

	if atomic.LoadInt32(&s.started) == 1 {
		return ErrStreamSubscribed
	}
	atomic.StoreInt32(&s.started, 1)

	interval := s.Interval
	if interval < minimumInterval {
		interval = minimumInterval
	}

	spotifyClient := s.Conn

	tokenExpierErrCnt := 0
	var preTrackID string
	for {
		// This loop is stopped
		select {
		case <-finishCh:
			return nil
		default:
			player, err := spotifyClient.PlayerCurrentlyPlaying()
			log.Println("Spotify streaming is working")
			if err != nil {
				if err != io.EOF {
					s.log(err)
				}
				serr, ok := err.(spotify.Error)

				if !ok {
					log.Fatalf("Expected spotify Error, got %T", err)
				}

				// If token is expired, try to renew client
				if serr.Status == http.StatusUnauthorized {
					spotifyClient, err = s.ReNewClient()
					tokenExpierErrCnt += 1

					if tokenExpierErrCnt > 3 {
						return nil
					}

					if err != nil {
						return err
					}
					continue
				}

				return err
			}
			tokenExpierErrCnt = 0

			if !player.Playing || player.Item == nil {
				preTrackID = ""
				time.Sleep(interval)
				continue
			}

			curTrackID := player.Item.ID.String()
			if preTrackID == curTrackID {
				time.Sleep(interval)
				continue
			}
			preTrackID = curTrackID

			go s.handle(player)
			time.Sleep(interval)
		}
	}
}

func (s *Stream) handle(playing *spotify.CurrentlyPlaying) {
	s.trackPlaying(playing, true)
	defer s.trackPlaying(playing, false)
	if s.Handler != nil {
		s.Handler.Serve(playing)
	}
}

func (s *Stream) RegisterOnShutdown(f func()) {
	s.mu.Lock()
	s.onShutdown = append(s.onShutdown, f)
	s.mu.Unlock()
}

func (s *Stream) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&s.inShutdown, 1)

	s.mu.Lock()
	s.closeDoneChanLocked()
	for _, f := range s.onShutdown {
		go f()
	}
	s.mu.Unlock()

	finished := make(chan struct{}, 1)
	go func() {
		s.activePlayingWg.Wait()
		finished <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finished:
		return nil
	}
}

func (s *Stream) StopStreaming() {
	finishCh <- 1
}

func (s *Stream) shuttingDown() bool {
	return atomic.LoadInt32(&s.inShutdown) != 0
}

func (s *Stream) trackPlaying(playing *spotify.CurrentlyPlaying, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activePlaying == nil {
		s.activePlaying = make(map[*spotify.CurrentlyPlaying]struct{})
	}
	if add {
		if !s.shuttingDown() {
			s.activePlaying[playing] = struct{}{}
			s.activePlayingWg.Add(1)
		}
	} else {
		delete(s.activePlaying, playing)
		s.activePlayingWg.Done()
	}
}

func (s *Stream) getDoneChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDoneChanLocked()
}

func (s *Stream) getDoneChanLocked() chan struct{} {
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}

func (s *Stream) closeDoneChanLocked() {
	ch := s.getDoneChanLocked()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (s *Stream) log(args ...interface{}) {
	if s.LoggerFunc != nil {
		args = append([]interface{}{name + ": "}, args...)
		s.LoggerFunc(args...)
	}
}

type LoggerFunc func(...interface{})

type Handler interface {
	Serve(message *spotify.CurrentlyPlaying)
}

type HandlerFunc func(playing *spotify.CurrentlyPlaying)

func (f HandlerFunc) Serve(playing *spotify.CurrentlyPlaying) {
	f(playing)
}
