package main

import (
	"time"
)

func TimeLocal(t time.Time, location string) time.Time {
	if location == "" {
		location = "Local"
	}
	loc, err := time.LoadLocation(location)
	if err == nil {
		t2 := t.In(loc)
		_, offset := t2.Zone()
		t = t.Add(-time.Duration(offset) * time.Second)
		t = t.In(loc)
	}

	return t
}
