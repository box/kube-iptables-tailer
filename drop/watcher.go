package drop

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/golang/glog"
	"io"
	"os"
	"time"
)

const fingerprintSize = 64 // using the first log in your iptables log file (should have length > 64) as fingerprint

// Watcher handles detecting any changes on the given file and passing those changes through Go Channel to be parsed.
type Watcher struct {
	watchFileName    string
	watchInterval    time.Duration
	lastReadPosition int64
	curFingerprint   string
}

// Init a watcher object and return its pointer
func InitWatcher(watchFileName string, watchInterval time.Duration) *Watcher {
	watcher := Watcher{watchFileName: watchFileName, watchInterval: watchInterval}
	return &watcher
}

// Run the watcher and insert newly found logs into given channel
func (watcher *Watcher) Run(logChangeCh chan<- string) {
	for range time.Tick(watcher.watchInterval) {
		glog.Infoln("Watching logs...")
		// check the file inside loop to get updated content at every watch interval
		watcher.checkFile(logChangeCh)
	}
}

// Open the watched file and check its content if it is opened successfully
func (watcher *Watcher) checkFile(logChangeCh chan<- string) {
	file, err := os.Open(watcher.watchFileName)
	if err != nil {
		glog.Errorf("Failed to open the file=%s, error=%v", watcher.watchFileName, err)
		return
	}
	defer closeFile(file)
	checkErr := watcher.check(file, logChangeCh)
	if checkErr != nil {
		glog.Errorf("Failed to check the content of file, error: %+v", checkErr)
	}
}

// Check the content from given input, and send changes to the channel
func (watcher *Watcher) check(input io.ReadSeeker, logChangeCh chan<- string) error {
	// check log rotation first from current input
	err := watcher.checkRotation(input)
	if err != nil {
		return err
	}

	// skip the content already read
	if _, err := input.Seek(watcher.lastReadPosition, 0); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	scanLines := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = bufio.ScanLines(data, atEOF)
		watcher.lastReadPosition += int64(advance)
		return
	}
	scanner.Split(scanLines)

	// send updated logs to channel
	for scanner.Scan() {
		newLog := scanner.Text()
		logChangeCh <- newLog
	}
	return nil
}

// Check rotation from the given input and update fingerprint if input is rotated
func (watcher *Watcher) checkRotation(input io.Reader) error {
	// get fingerprint of the input
	bytes := make([]byte, fingerprintSize)
	sizeRead, err := input.Read(bytes)
	// check sizeRead before err according to documentation of Reader.Read()
	if sizeRead < fingerprintSize {
		return errors.New(fmt.Sprint("Error getting fingerprint, insufficient content."))
	}
	if err != nil {
		return errors.New(fmt.Sprintf("Error checking rotation: error=%+v", err.Error()))
	}
	fingerprint := string(bytes[:])
	if fingerprint != watcher.curFingerprint {
		// need to reset the watcher because the log file has been rotated (fingerprint didn't match)
		watcher.reset(fingerprint)
	}
	return nil
}

// Reset watcher's lastReadPosition and update its fingerprint
func (watcher *Watcher) reset(fingerprint string) {
	watcher.lastReadPosition = 0
	watcher.curFingerprint = fingerprint
}

// Helper function to close the file properly
func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		glog.Errorf("Error while closing the file: %+v", err)
	}
}
