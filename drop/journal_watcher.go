// +build !cgo

package drop

import "go.uber.org/zap"

type JournalWatcher struct {
}

func InitJournalWatcher(_ string) *JournalWatcher {
	zap.L().Fatal("you need to build with cgo for journal watching support")
	return nil
}

// Run the watcher and insert newly found logs into given channel
func (watcher *JournalWatcher) Run(_ chan<- string) {
	zap.L().Fatal("you need to build with cgo for journal watching support")
}
