package event

import (
	"errors"
	"fmt"
	"github.com/box/kube-iptables-tailer/drop"
	"github.com/box/kube-iptables-tailer/metrics"
	"github.com/box/kube-iptables-tailer/util"
	"github.com/cenkalti/backoff"
	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"net"
	"os"
	"time"
)

// Poster handles submitting Kubernetes Events to Pods running in the cluster.
type Poster struct {
	kubeClient         *kubernetes.Clientset
	recorder           record.EventRecorder
	eventSubmitTimeMap map[string]time.Time // (srcIP+dstIP) as key, posted time as value
	backoff            backoff.BackOff      // used for retry when api server is down
	locator            Locator
}

// Init Poster and return its pointer
func InitPoster() (*Poster, error) {
	kubeClient, err := initKubeClient()
	if err != nil {
		return nil, err
	}
	recorder := initEventRecorder(kubeClient)

	exponentialBackOff := backoff.NewExponentialBackOff()
	// stop retrying if PacketDropExpirationMinutes have elapsed
	expiredMinutes := int64(util.GetEnvIntOrDefault(
		util.PacketDropExpirationMinutes, util.DefaultPacketDropExpirationMinutes))
	exponentialBackOff.MaxElapsedTime = time.Duration(expiredMinutes) * time.Minute

	locator, err := NewApiServerPodLocator(kubeClient)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error creating locator: %+v", err))
	}

	return &Poster{
		kubeClient:         kubeClient,
		recorder:           recorder,
		eventSubmitTimeMap: make(map[string]time.Time),
		backoff:            exponentialBackOff,
		locator:            locator,
	}, nil
}

// Run the poster by handling PacketDrop from given channel. Apply exponential backoff if server is down.
func (poster *Poster) Run(stopCh <-chan struct{}, packetDropCh <-chan drop.PacketDrop) {
	go poster.locator.Run(stopCh)

	for packetDrop := range packetDropCh {
		// setup a backoff and retry mechanism
		retryOperation := func() error {
			return poster.handle(packetDrop)
		}

		errorNotifier := func(err error, t time.Duration) {
			glog.Errorf("Error retrying packet drop handling, backing off: "+
				"packetDrop=%+v, retryIn=%v secs, error=%v",
				packetDrop, err, t.Seconds())
		}

		if err := backoff.RetryNotify(retryOperation, poster.backoff, errorNotifier); err != nil {
			glog.Errorf("Error retrying packet drop handling, giving up: "+
				"packetDrop=%+v, error=%v", packetDrop, err)
		}

		// reset the backoff to handle the next packet drop
		poster.backoff.Reset()
	}
}

// Handle the given PacketDrop, return error if api server does not work
func (poster *Poster) handle(packetDrop drop.PacketDrop) error {
	if poster.shouldIgnore(packetDrop) {
		return nil
	}
	srcPod, err := poster.locator.LocatePod(packetDrop.SrcIP)
	if err != nil {
		return err
	}
	dstPod, err := poster.locator.LocatePod(packetDrop.DstIP)
	if err != nil {
		return err
	}

	// update metrics and post events
	srcName := getNamespaceOrHostName(srcPod, packetDrop.SrcIP, net.DefaultResolver)
	dstName := getNamespaceOrHostName(dstPod, packetDrop.DstIP, net.DefaultResolver)
	if srcPod != nil && !srcPod.Spec.HostNetwork {
		message := getPacketDropMessage(dstName, packetDrop.DstIP, send)
		if err := poster.submitEvent(srcPod, message); err != nil {
			return err
		}
	}
	if dstPod != nil && !dstPod.Spec.HostNetwork {
		message := getPacketDropMessage(srcName, packetDrop.SrcIP, receive)
		if err := poster.submitEvent(dstPod, message); err != nil {
			return err
		}
	}
	metrics.GetInstance().ProcessPacketDrop(srcName, dstName)
	// update poster's eventSubmitTimeMap
	poster.eventSubmitTimeMap[packetDrop.SrcIP+packetDrop.DstIP] = time.Now()
	return nil
}

// Check if given PacketDrop should be ignored
func (poster *Poster) shouldIgnore(packetDrop drop.PacketDrop) bool {
	// ignore if the given packetDrop is out of date
	if packetDrop.IsExpired() {
		glog.Infof("Ignoring expired packet drop: packetDrop=%+v", packetDrop)
		return true
	}
	// ignore if the event has been posted within the defined time period
	logTime, _ := packetDrop.GetLogTime() //  the error would be handled in expiration check called above
	key := packetDrop.SrcIP + packetDrop.DstIP
	lastPostedTime := poster.eventSubmitTimeMap[key]
	repeatEventIntervalMinutes := float64(util.GetEnvIntOrDefault(
		util.RepeatedEventIntervalMinutes, util.DefaultRepeatedEventIntervalMinutes))
	if !lastPostedTime.IsZero() && logTime.Sub(lastPostedTime).Minutes() <= repeatEventIntervalMinutes {
		glog.Infof("Ignoring duplicate packet drop: packetDrop=%+v", packetDrop)
		return true
	}

	return false
}

// Submit an event using kube API with message attached
func (poster Poster) submitEvent(pod *v1.Pod, message string) error {
	ref, err := reference.GetReference(scheme.Scheme, pod)
	if err != nil {
		return err
	}
	reason := util.GetEnvStringOrDefault(util.KubeEventDisplayReason, util.DefaultKubeEventDisplayReason)
	poster.recorder.Event(ref, v1.EventTypeWarning, reason, message)
	glog.Infof("Submitted event: pod=%s, message=%s", ref.Name, message)

	return nil
}

// Init Kube Client for poster object
func initKubeClient() (*kubernetes.Clientset, error) {
	// this returns a config object which configures both the token and TLS
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// override kube api server if it is set (necessary if kube-proxy isn't properly set up)
	apiServerOverride := getKubeApiServerOverride()
	if apiServerOverride != "" {
		kubeConfig.Host = apiServerOverride
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	kubeClient.CoreV1()

	return kubeClient, nil
}

// Init Event Recorder for poster object
func initEventRecorder(kubeClient *kubernetes.Clientset) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.V(5).Infof)
	eventBroadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	component := util.GetEnvStringOrDefault(
		util.KubeEventSourceComponentName, util.DefaultKubeEventSourceComponentName)
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: component})

	return recorder
}

// Helper function to get kube api server override, return empty String if no override
func getKubeApiServerOverride() string {
	if server := os.Getenv(util.KubeApiServer); server != "" {
		return server
	}
	return ""
}
