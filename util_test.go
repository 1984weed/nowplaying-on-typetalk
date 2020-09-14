package main

import (
	"testing"
	"time"
)

func TestTimeLocalShouldReturnConvertedUTC(t *testing.T) {
	t1 := time.Date(2020, time.October, 1, 13, 0, 0, 0, time.UTC)
	want := "2020-10-01 13:00:00 +0900 JST"
	got := TimeLocal(time.Time(t1), "Asia/Tokyo").String()

	if got != want {
		t.Errorf("TimeLocal return wrong time: got %s, want %s ",
			got, want)
	}
}
