package event

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/box/kube-iptables-tailer/util"
	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// DnsResolver allows for mocking out the functionality of net.DefaultResolver when testing getPacketDropMessage()
type DnsResolver interface {
	LookupAddr(context context.Context, ip string) (names []string, err error)
}

type NodeGetter interface {
	Get(name string, options metav1.GetOptions) (*v1.Node, error)
}

type TrafficDirection int

const (
	send TrafficDirection = iota
	receive
)

func (td TrafficDirection) String() string {
	switch td {
	case send:
		return "SEND"
	case receive:
		return "RECEIVE"
	default:
		return ""
	}
}

const indexerName = "podIp"

type Locator interface {
	Run(stopCh <-chan struct{})
	LocatePod(ip string) (*v1.Pod, error)
}

// PodLocator handles the process of locating corresponding Pods having iptables packet drops in Kubernetes cluster.
type PodLocator struct {
	informer cache.SharedIndexInformer
}

/*
 * Returns a locator that pulls pod data from the apiserver
 */
func NewApiServerPodLocator(client *kubernetes.Clientset) (*PodLocator, error) {
	listWatch := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(), "pods", v1.NamespaceAll,
		fields.AndSelectors(fields.OneTermEqualSelector("status.phase", "Running")))

	return getPodLocator(listWatch), nil
}

func getPodLocator(listerWatcher cache.ListerWatcher) *PodLocator {
	// initialize the informer which has a common cache
	informer := cache.NewSharedIndexInformer(listerWatcher, &v1.Pod{}, time.Hour,
		cache.Indexers{indexerName: podIPIndexer()})

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			zap.L().Debug(
				"Add func",
				zap.String("object", fmt.Sprintf("%+v", util.PrettyPrint(obj))),
			)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			zap.L().Debug("Update func",
				zap.String("old_object", fmt.Sprintf("%+v", util.PrettyPrint(oldObj))),
				zap.String("new_object", fmt.Sprintf("%+v", util.PrettyPrint(newObj))),
			)
		},
	})

	return &PodLocator{
		informer: informer,
	}
}

func podIPIndexer() func(obj interface{}) ([]string, error) {
	indexFunc := func(obj interface{}) ([]string, error) {
		if pod, ok := obj.(*v1.Pod); ok {
			zap.L().Info("Indexing pod",
				zap.String("pod_name", pod.Name),
				zap.String("pod_namespace", pod.Namespace),
				zap.String("pod_ip", pod.Status.PodIP),
			)
			return []string{pod.Status.PodIP}, nil
		} else {
			return []string{""}, fmt.Errorf("unable to cast object to *v1.Pod: obj=%+v",
				util.PrettyPrint(obj))
		}
	}
	return indexFunc
}

func (locator *PodLocator) Run(stopCh <-chan struct{}) {
	go locator.informer.Run(stopCh)

	// wait for the cache to synchronize for the first time
	if !cache.WaitForCacheSync(stopCh) {
		zap.L().Fatal("Timed out waiting for pod cache to sync")
	}
}

func (locator *PodLocator) LocatePod(ip string) (*v1.Pod, error) {
	items, err := locator.informer.GetIndexer().ByIndex(indexerName, ip)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error looking up pod: ip=%v", ip))
	} else if len(items) > 0 {
		if pod, ok := items[0].(*v1.Pod); ok {
			zap.L().Debug(
				"Pod found",
				zap.String("pod_name", pod.Name),
				zap.String("pod_namespace", pod.Namespace),
				zap.String("pod_ip", ip),
				zap.String("pod_node", pod.Spec.NodeName),
			)
			return pod, nil
		}
	}
	zap.L().Warn("Pod not found", zap.String("ip", ip))
	return nil, nil
}

/*
 * 1. If a pod is not using host networking, return its namespace name, or if the POD_IDENTIFIER
 *    environment variable is set to 'pod', return the pod name.
 * 2. If a pod is using host networking, return its hostname. This is because multiple pods may
 *    be sharing the host IP, therefore it's impossible to distinguish which pod is the src/dst.
 * 3. If no pod is found, attempt to resolve the IP to hostname.
 */
func getNamespaceOrHostName(pod *v1.Pod, ip string, resolver DnsResolver) string {
	if pod != nil {
		if !pod.Spec.HostNetwork {
			zap.L().Debug(
				"Pod does not have host networking",
				zap.String("pod_name", pod.Name),
				zap.String("pod_namespace", pod.Namespace),
				zap.String("pod_ip", pod.Status.PodIP),
				zap.String("pod_node", pod.Spec.NodeName),
			)
			identifier := util.GetEnvStringOrDefault(util.PodIdentifier, util.DefaultPodIdentifier)
			switch identifier {
			case "name":
				return pod.Name
			case "label":
				labelKey := util.GetRequiredEnvString(util.PodIdentifierLabel)
				if labelValue, ok := pod.Labels[labelKey]; ok {
					return labelValue
				}
				return pod.Name
			case "namespace":
				return pod.Namespace
			case "name_with_namespace":
				return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
			}
			return pod.Namespace
		}
		if pod.Spec.NodeName != "" {
			zap.L().Debug(
				"Pod has host networking, using node value",
				zap.String("pod_name", pod.Name),
				zap.String("pod_namespace", pod.Namespace),
				zap.String("pod_ip", pod.Status.PodIP),
				zap.String("pod_node", pod.Spec.NodeName),
			)
			return pod.Spec.NodeName
		}
	}
	zap.L().Debug("Pod spec not found, using reverse dns lookup", zap.String("ip", ip))
	return getHostName(resolver, ip)
}

// Helper function to construct packet drop message
func getPacketDropMessage(otherSideServiceName string, ip string, port string, proto string, direction TrafficDirection) string {
	var buffer bytes.Buffer
	buffer.WriteString("Packet dropped")
	// append traffic direction
	if direction == receive {
		buffer.WriteString(" when receiving traffic from ")
	} else if direction == send {
		buffer.WriteString(" when sending traffic to ")
	}
	// append other side's service name
	buffer.WriteString(otherSideServiceName)
	if otherSideServiceName != ip && ip != "" {
		buffer.WriteString(fmt.Sprintf(" (%s)", ip))
	}
	buffer.WriteString(fmt.Sprintf(" on port %s/%s", port, proto))
	return buffer.String()
}

// Get the host name of given ip from dns, return IP address if host name cannot be found
func getHostName(resolver DnsResolver, ipAddress string) string {
	zap.L().Debug("Performing dns lookup")
	addr, err := resolver.LookupAddr(context.Background(), ipAddress)
	if err != nil || len(addr) == 0 {
		if err != nil {
			zap.L().Info(
				"Unable to resolve address",
				zap.String("ip", ipAddress),
				zap.String("error", err.Error()),
			)
		}
		zap.L().Debug("fallback, using ip address", zap.String("ip", ipAddress))
		return ipAddress
	}

	zap.L().Debug("Using ip address from lookup", zap.String("ip", addr[0]))
	return addr[0] // currently returning the first host name found
}
