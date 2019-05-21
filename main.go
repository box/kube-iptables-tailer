package main

import (
	"flag"
	"fmt"
	"github.com/box/kube-iptables-tailer/drop"
	"github.com/box/kube-iptables-tailer/event"
	"github.com/box/kube-iptables-tailer/metrics"
	"github.com/box/kube-iptables-tailer/util"
	"github.com/golang/glog"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	flag.Parse()

	stopCh := make(chan struct{})
	var vg sync.WaitGroup
	vg.Add(4)

	go startMetricsServer(util.GetEnvIntOrDefault(util.MetricsServerPort, util.DefaultMetricsServerPort))

	//prepare channels
	logChangeCh := make(chan string)
	bufferSize := util.GetEnvIntOrDefault(util.PacketDropChannelBufferSize, util.DefaultPacketDropsChannelBufferSize)
	packetDropCh := make(chan drop.PacketDrop, bufferSize)

	go startPoster(packetDropCh, stopCh)

	logPrefix := util.GetRequiredEnvString(util.IptablesLogPrefix)
	go startParsing(logPrefix, logChangeCh, packetDropCh)

	if journalDir := os.Getenv(util.JournalDirectory); journalDir != "" {
		go startJournalWatcher(journalDir, logChangeCh)
	} else {
		fileName := util.GetRequiredEnvString(util.IptablesLogPath)
		watchSeconds := util.GetEnvIntOrDefault(util.WatchLogsIntervalSeconds, util.DefaultWatchLogsIntervalSecond)
		go startWatcher(fileName, time.Duration(watchSeconds)*time.Second, logChangeCh)
	}

	vg.Wait()
	close(stopCh)
}

//Start metrics server on given listen address
func startMetricsServer(port int) {
	http.Handle("/metrics", metrics.GetInstance().GetHandler())
	err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
	if err != nil {
		glog.Fatal(err) // exit the program if it fails to serve metrics
	}
}

//Start poster with given channel of PacketDrop
func startPoster(packetDropCh <-chan drop.PacketDrop, stopCh <-chan struct{}) {
	poster, err := event.InitPoster()
	if err != nil {
		// cannot run the service without poster being created successfully
		glog.Fatal("Cannot init event poster", err)
	}
	poster.Run(stopCh, packetDropCh)
}

//Start watcher with given filename to watch, interval to check, and channel to store results
func startWatcher(fileName string, interval time.Duration, logChangeCh chan<- string) {
	watcher := drop.InitWatcher(fileName, interval)
	watcher.Run(logChangeCh)
}

//Start journal watcher with given journal directory to watch, and channel to store results
func startJournalWatcher(journalDir string, logChangeCh chan<- string) {
	jWatcher := drop.InitJournalWatcher(journalDir)
	jWatcher.Run(logChangeCh)
}

//Start parsing process with given channel to get raw logs and another channel to store paring results
func startParsing(logPrefix string, logChangeCh <-chan string, packetDropCh chan<- drop.PacketDrop) {
	drop.RunParsing(logPrefix, logChangeCh, packetDropCh)
}
