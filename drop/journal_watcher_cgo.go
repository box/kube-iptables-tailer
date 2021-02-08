// +build cgo

package drop

import (
	"fmt"
	"strings"
	"time"

	"github.com/box/kube-iptables-tailer/util"
	"github.com/coreos/go-systemd/sdjournal"
	"go.uber.org/zap"
)

// Watcher handles detecting any changes on the given journal and passing those changes through Go Channel to be parsed.
type JournalWatcher struct {
	journalDir string
}

// Init a journal watcher object and return its pointer
func InitJournalWatcher(journalDir string) *JournalWatcher {
	watcher := JournalWatcher{journalDir: journalDir}
	return &watcher
}

// Run the watcher and insert newly found logs into given channel
func (watcher *JournalWatcher) Run(logChangeCh chan<- string) {
	reader, err := sdjournal.NewJournalReader(sdjournal.JournalReaderConfig{
		Path:        watcher.journalDir,
		NumFromTail: 1,
		Matches: []sdjournal.Match{{
			Field: "SYSLOG_IDENTIFIER",
			Value: "kernel",
		}},
		Formatter: func(entry *sdjournal.JournalEntry) (s string, e error) {
			msg, ok := entry.Fields["MESSAGE"]
			if !ok {
				return "", fmt.Errorf("no MESSAGE field present in journal entry")
			}

			hostname, ok := entry.Fields["_HOSTNAME"]
			if !ok {
				return "", fmt.Errorf("no _HOSTNAME field present in journal entry")
			}

			return strings.Join([]string{
				time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond)).
					Format(util.DefaultPacketDropLogTimeLayout),
				hostname,
				msg,
			}, " ") + "\n", nil
		},
	})
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	if err := reader.Follow(nil, &lineWriter{logChangeCh}); err != nil {
		zap.L().Fatal(err.Error())
	}
}

type lineWriter struct {
	logChangeCh chan<- string
}

func (lw *lineWriter) Write(buf []byte) (n int, err error) {
	lw.logChangeCh <- string(buf)
	return len(buf), nil
}
