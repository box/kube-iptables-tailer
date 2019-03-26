package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type TestCase struct {
	src string
	dst string
}

// Test if Metrics can process packetDropsCount with its namespace, other side's service name, and traffic direction
func TestMetricsProcessPacketDrops(t *testing.T) {
	// key: TestCase for packet drop; value: number of count it happens
	testCaseMap := make(map[TestCase]int)
	// construct test case with namespace "test-namespace-i" and count i
	// for trafficDirection, set it "SEND" if i is even, "RECEIVE" if i is odd
	for i := 1; i <= 5; i++ {
		testCase := TestCase{
			src: fmt.Sprintf("test-namespace-%v", i),
			dst: fmt.Sprintf("other-side-service-name-%v", i),
		}
		testCaseMap[testCase] = i
	}
	// simulate the process of Metrics updating packetDropsCount
	// trafficDirection is simulated as sending when namespace has odd number and receiving when it has even number
	for testCase := range testCaseMap {
		for i := 0; i < testCaseMap[testCase]; i++ {
			GetInstance().ProcessPacketDrop(testCase.src, testCase.dst)
		}
	}
	// check the actual metrics raw data with expected string
	metricsResult := requestContentBody(GetInstance().GetHandler())
	for testCase, count := range testCaseMap {
		expected := getPacketDropsCountMetricsString(testCase, count)
		if !strings.Contains(metricsResult, expected) {
			t.Fatalf("Expected %s, but couldn't find it from result %s", expected, metricsResult)
		}

	}
}

// Helper function to get string showing in metrics of given test case and its count
func getPacketDropsCountMetricsString(testCase TestCase, count int) string {
	// tags must be in alphabetical order
	return fmt.Sprintf("packet_drops_count{dst=\"%s\",src=\"%s\"} %v", testCase.dst, testCase.src, count)
}

// Helper function to request content body from the handler.
func requestContentBody(handler http.Handler) string {
	req, _ := http.NewRequest("GET", "", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Body.String()
}
