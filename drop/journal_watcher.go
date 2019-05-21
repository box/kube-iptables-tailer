// +build !cgo

package drop

import "github.com/golang/glog"

type JournalWatcher struct {
}

func InitJournalWatcher(_ string) *JournalWatcher {
	glog.Fatal("you need to build with cgo for journal watching support")
	return nil
}

// Run the watcher and insert newly found logs into given channel
func (watcher *JournalWatcher) Run(_ chan<- string) {
	glog.Fatal("you need to build with cgo for journal watching support")
}
