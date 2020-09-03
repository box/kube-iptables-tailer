package util

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/glog"
)

func PrettyPrint(i interface{}) string {
	s, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		glog.Errorf("Error marshaling JSON: obj=%+v", i)
		return fmt.Sprintf("%+v", i)
	} else {
		return string(s)
	}
}

// Utility functions for packet drop testing
func GetExpiredTimeIn(expirationMinutes int) time.Time {
	duration := time.Duration(expirationMinutes) * time.Minute
	// add one more minute than given expiration to make sure the time is expired
	return time.Now().Add(-duration - time.Minute)
}
