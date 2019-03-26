package drop

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

const TestLog1 = "2018-06-04T01:02:03.178452-07:00 hostname logPrefix: SRC=11.111.11.111 DST=22.222.22.222"
const TestLog2 = "2019-02-04T04:05:06.178452-07:00 hostname logPrefix: SRC=22.222.22.222 DST=11.111.11.111"

//Test if init the watcher object works (InitWatcher() includes the Reset() method)
func TestWatcherReset(t *testing.T) {
	watcher := InitWatcher("", time.Second)
	watcher.lastReadPosition = 256
	watcher.curFingerprint = "test-fingerprint"
	expectedLastReadPosition := int64(0)
	expectedFingerprint := "new-fingerprint"

	watcher.reset(expectedFingerprint)
	resultLastReadPosition := watcher.lastReadPosition
	resultFingerprint := watcher.curFingerprint

	if expectedLastReadPosition != resultLastReadPosition {
		t.Fatalf("Expected last read position %v, but got actual last read position %v",
			expectedLastReadPosition,
			resultLastReadPosition)
	}
	if expectedFingerprint != resultFingerprint {
		t.Fatalf("Expected fingerprint %s, but got actual fingerprint %s",
			expectedFingerprint,
			resultFingerprint)
	}
}

// Test if checking file works
func TestCheckFile(t *testing.T) {
	fileName := "test-1.txt"
	// create the test file and set its permission
	err := ioutil.WriteFile(fileName, []byte(TestLog1), 0755)
	if err != nil {
		t.Fatalf("Cannot create the test file, err=%+v", err)
	}
	// test if the file can be opened and checked
	watcher := InitWatcher(fileName, time.Second)
	channel := make(chan string)
	go watcher.checkFile(channel)
	result := <-channel
	if result != TestLog1 {
		t.Fatalf("Expected %s, but got result %s", TestLog1, result)
	}
	// remove the test file created above
	err = os.Remove(fileName)
	if err != nil {
		t.Fatalf("Cannot delete the test file, err=%+v", err)
	}
}

// Test if the basic checking content works
func TestCheckContent(t *testing.T) {
	watcher := InitWatcher("", time.Second)
	channel := make(chan string)
	expected := TestLog1
	input := strings.NewReader(expected)
	go watcher.check(input, channel)

	result := <-channel
	if result != expected {
		t.Fatalf("Expected %s, but got result %s", expected, result)
	}
}

// Test if checking updated content works
func TestCheckUpdate(t *testing.T) {
	watcher := InitWatcher("", time.Second)
	channel := make(chan string)
	expected1 := TestLog1
	expected2 := "Updated Input."

	var buffer bytes.Buffer
	buffer.WriteString(expected1)
	input := strings.NewReader(buffer.String())
	go watcher.check(input, channel)
	result1 := <-channel

	buffer.WriteString(expected2)
	updatedInput := strings.NewReader(buffer.String())
	go watcher.check(updatedInput, channel)
	result2 := <-channel

	if result1 != expected1 {
		t.Fatalf("Expected %s, but got result %s", expected1, result1)
	}
	if result2 != expected2 {
		t.Fatalf("Expected %s, but got result %s", expected2, result2)
	}
}

// Test if checking rotated input works
func TestCheckRotation(t *testing.T) {
	watcher := InitWatcher("", time.Second)
	channel := make(chan string)
	expected := TestLog1
	input := strings.NewReader(expected)
	go watcher.check(input, channel)
	result := <-channel

	// updated the date of log as mock of rotating
	rotatedExpected := TestLog2
	rotatedInput := strings.NewReader(rotatedExpected)
	go watcher.check(rotatedInput, channel)
	rotatedResult := <-channel

	if result != expected {
		t.Fatalf("Expected %s, but got result %s", expected, result)
	}
	if rotatedResult != rotatedExpected {
		t.Fatalf("Expected %s, but got result %s", rotatedExpected, rotatedResult)
	}
}
