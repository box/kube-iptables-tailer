package util

import (
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"time"
)

// PrettyPrint returns the string in JSON format
func PrettyPrint(i interface{}) string {
	s, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		glog.Errorf("Error marshaling JSON: obj=%+v", i)
		return fmt.Sprintf("%+v", i)
	}
	return string(s)

}

// GetExpiredTimeInString returns an expired time which is used in packet drop testing
func GetExpiredTimeInString(expirationMinutes int, timeFormat string) string {
	duration := time.Duration(expirationMinutes) * time.Minute
	// add one more minute than given expiration to make sure the time is expired
	return time.Now().Add(-duration - time.Minute).Format(timeFormat)
}
