package event

import (
	"bufio"
	"errors"
	"flag"
	"github.com/box/kube-iptables-tailer/drop"
	"github.com/box/kube-iptables-tailer/util"
	"github.com/cenkalti/backoff"
	"k8s.io/api/core/v1"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

type DummyLocator struct{}

func (loc *DummyLocator) Run(stopCh <-chan struct{}) {
	// no-op
}
func (loc *DummyLocator) LocatePod(ip string) (*v1.Pod, error) {
	return nil, errors.New("simulating a pod lookup error")
}

// Helper function for testing
func getPresentPacketDrop() drop.PacketDrop {
	curTime := time.Now().Format(drop.PacketDropLogTimeLayout)
	packetDrop := drop.PacketDrop{LogTime: curTime}
	return packetDrop
}

// Test if poster.shouldIgnore() works for timed out PacketDrop
// by subtracting the PacketDropExpirationMinutes and an additional arbitrary amount of time
func TestShouldIgnoreTimeout(t *testing.T) {
	poster := Poster{} // cannot use InitPoster() directly because the test may not have k8s environment

	// create an obsolete time by subtracting the eventDurationMinutes
	expiredTime := util.GetExpiredTimeInString(
		util.DefaultPacketDropExpirationMinutes, drop.PacketDropLogTimeLayout)
	timedOutPacketDrop := drop.PacketDrop{LogTime: expiredTime}

	result := poster.shouldIgnore(timedOutPacketDrop)
	if result != true {
		t.Fatalf("Expected %v, but got result %v", true, result)
	}
}

// Test if poster.shouldIgnore() works for same PacketDrops happened in specific period of time
func TestShouldIgnoreSameEvent(t *testing.T) {
	poster := Poster{}
	poster.eventSubmitTimeMap = make(map[string]time.Time)
	curTime := time.Now()
	logTime := curTime.Format(drop.PacketDropLogTimeLayout)
	packetDrop := drop.PacketDrop{LogTime: logTime, SrcIP: "1.1.1", DstIP: "2.2.2"}
	// insert a mocked time when same event was submitted recently (within the interval threshold)
	poster.eventSubmitTimeMap[packetDrop.SrcIP+packetDrop.DstIP] =
		curTime.Add(-util.DefaultRepeatedEventIntervalMinutes*time.Minute + time.Minute)

	result := poster.shouldIgnore(packetDrop)
	if result != true {
		t.Fatalf("Expected %v, but got result %v", true, result)
	}
}

// Test if poster.shouldIgnore() works for PacketDrop which is present and never posted before
func TestShouldIgnoreNot(t *testing.T) {
	poster := Poster{}

	result := poster.shouldIgnore(getPresentPacketDrop())
	if result != false {
		t.Fatalf("Expected %v, but got result %v", false, result)
	}
}

// Test if poster.Run() correctly applies exponential backoff when api server is down
func TestPosterRunExponentialBackoff(t *testing.T) {
	// prepare to capture error logs from os.Stderr
	flag.Set("logtostderr", "true")
	flag.Parse()
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer

	// setup customized exponential backoff for better testing its functionality
	// the formula used to calculate the next retry interval in our backoff library is:
	// RetryInterval = Multiplier * CurrentInterval * (random in [1 - RandomizationFactor, 1 + RandomizationFactor])
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = 50 * time.Millisecond
	exponentialBackoff.MaxElapsedTime = time.Second
	exponentialBackoff.Multiplier = 2
	exponentialBackoff.RandomizationFactor = 0

	// start poster.Run with simulating API server is down
	poster := Poster{}
	poster.locator = &DummyLocator{}
	poster.kubeClient = nil // set the kubeClient nil to simulate the kube API server is down
	poster.backoff = exponentialBackoff
	stopCh := make(chan struct{})
	packetDropCh := make(chan drop.PacketDrop, 1) // just need one drop to start backing off
	packetDropCh <- getPresentPacketDrop()
	// close the channel after inserting the drop so that poster.Run() won't run and block forever
	close(packetDropCh)
	poster.Run(stopCh, packetDropCh)

	// set os.Stderr back to original and collect the error logs from poster.Run()
	os.Stderr = originalStderr
	writer.Close()
	var logs []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		log := scanner.Text()
		logs = append(logs, log)
	}
	reader.Close()

	// compare time gaps between collected error logs with defined exponential durations
	expectedIntervals := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1000 * time.Millisecond,
	}
	tolerance := 10 * time.Millisecond
	prev := time.Now()
	for i, log := range logs {
		logTime, err := time.Parse("15:04:05.000000", strings.Split(log, " ")[1])
		if err != nil {
			t.Fatal(err)
		}
		// exponential backoff starts after the first request to api server failed
		// the first exponential time gap we get is from third request - second request
		if i >= 2 && !timeMatches(logTime.Sub(prev), expectedIntervals[i-2], tolerance) {
			t.Fatalf("expected interval %v, but got result %v", expectedIntervals[i-2], logTime.Sub(prev))
		}
		prev = logTime
	}
}

// Helper function to check if given two durations are equal with the given tolerance
func timeMatches(d1, d2, tolerance time.Duration) bool {
	diff := float64(d1 - d2)
	return math.Abs(diff) < float64(tolerance)
}
