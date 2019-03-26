package event

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/api/core/v1"
	"net"
	"testing"
)

type MockDnsResolver struct {
	hostNames map[string][]string
	err       error
}

// Helper function to init MockDnsResolver with empty hostNames
func initMockDnsResolver() *MockDnsResolver {
	return &MockDnsResolver{hostNames: make(map[string][]string), err: nil}
}

// Function to Mock DNSResolver
func (r MockDnsResolver) LookupAddr(context context.Context, ip string) ([]string, error) {
	return r.hostNames[ip], r.err
}

// Test if getNamespaceOrHostName() works
func TestGetServiceNameFromIP(t *testing.T) {
	// test for pod not using hostNetworking
	expected := "test-namespace"
	pod := &v1.Pod{}
	pod.Namespace = expected
	pod.Spec.HostNetwork = false
	result := getNamespaceOrHostName(pod, "", net.DefaultResolver)
	if result != expected {
		t.Fatalf("Expected: %v, but got result: %v", expected, result)
	}

	// test for pod using hostNetworking but without spec.NodeName
	expectedDns := "test-hostname-dns"
	hostIP := "123.456.789"
	mockedResolver := initMockDnsResolver()
	mockedResolver.hostNames[hostIP] = []string{expectedDns}
	pod.Spec.HostNetwork = true
	result = getNamespaceOrHostName(pod, hostIP, mockedResolver)
	if result != expectedDns {
		t.Fatalf("Expected: %v, but got result: %v", expectedDns, result)
	}

	// test for pod using hostNetworking but with spec.NodeName
	expected = "test-host-name"
	pod.Spec.NodeName = expected
	result = getNamespaceOrHostName(pod, hostIP, mockedResolver)
	if result != expected {
		t.Fatalf("Expected: %v, but got result: %v", expected, result)
	}

	// test for empty pod
	result = getNamespaceOrHostName(nil, hostIP, mockedResolver)
	if result != expectedDns {
		t.Fatalf("Expected: %v, but got result: %v", expectedDns, result)
	}
}

// Test if getPacketDropMessage() works for pods
func TestGetPacketDropMessageForPods(t *testing.T) {
	namespace := "pod-name-test"
	testPod := &v1.Pod{}
	testPod.Namespace = namespace
	ipAddress := "123.456.789"
	serviceName := getNamespaceOrHostName(testPod, ipAddress, net.DefaultResolver)
	// test send traffic
	resultSending := getPacketDropMessage(serviceName, ipAddress, send)
	expectedSending := fmt.Sprintf("Packet dropped when sending traffic to %s (%s)",
		namespace, ipAddress)
	if resultSending != expectedSending {
		t.Fatalf("Expected: %v, but got result: %v", expectedSending, resultSending)
	}

	// test receive traffic
	resultReceiving := getPacketDropMessage(serviceName, ipAddress, receive)
	expectedReceiving := fmt.Sprintf("Packet dropped when receiving traffic from %s (%s)",
		namespace, ipAddress)
	if resultReceiving != expectedReceiving {
		t.Fatalf("Expected: %v, but got result: %v", expectedReceiving, resultReceiving)
	}
}

// Test if getPacketDropMessage() works for hosts
func TestGetPacketDropMessageForHosts(t *testing.T) {
	// test when DNS lookup exists
	ipAddress := "123.456.789"
	hostName := "mocked-host"
	mockedResolver := initMockDnsResolver()
	mockedResolver.hostNames[ipAddress] = []string{hostName}
	serviceName := getNamespaceOrHostName(nil, ipAddress, mockedResolver)

	// test send traffic
	resultSending := getPacketDropMessage(serviceName, ipAddress, send)
	expectedSending := fmt.Sprintf("Packet dropped when sending traffic to %s (%s)",
		hostName, ipAddress)
	if resultSending != expectedSending {
		t.Fatalf("Expected: %v, but got result: %v", expectedSending, resultSending)
	}

	// test receive traffic
	resultReceiving := getPacketDropMessage(serviceName, ipAddress, receive)
	expectedReceiving := fmt.Sprintf("Packet dropped when receiving traffic from %s (%s)",
		hostName, ipAddress)
	if resultReceiving != expectedReceiving {
		t.Fatalf("Expected: %v, but got result: %v", expectedReceiving, resultReceiving)
	}

	// test when DNS lookup returns empty hostname, should return IP address
	mockedResolver = initMockDnsResolver()
	serviceName = getNamespaceOrHostName(nil, ipAddress, mockedResolver)
	resultDnsEmpty := getPacketDropMessage(serviceName, ipAddress, send)
	expectedDnsEmpty := fmt.Sprintf("Packet dropped when sending traffic to %s", ipAddress)
	if resultSending != expectedSending {
		t.Fatalf("Expected: %v, but got result: %v", expectedDnsEmpty, resultDnsEmpty)
	}

	// test when DNS lookup fails
	mockedResolver = initMockDnsResolver()
	mockedResolver.err = errors.New("DNS lookup fails")
	serviceName = getNamespaceOrHostName(nil, ipAddress, mockedResolver)
	resultDnsFails := getPacketDropMessage(serviceName, ipAddress, receive)
	expectedDnsFails := fmt.Sprintf("Packet dropped when sending traffic to %s", ipAddress)
	if resultSending != expectedSending {
		t.Fatalf("Expected: %v, but got result: %v", expectedDnsFails, resultDnsFails)
	}
}
