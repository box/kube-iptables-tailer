package drop

import (
	"fmt"
	"testing"
	"time"

	"github.com/box/kube-iptables-tailer/util"
)

const (
	testHostname          = "hostname"
	testLogPrefix         = "log-prefix"
	testSrcIP             = "11.111.11.111"
	testSrcPort           = "56789"
	testDstIP             = "22.222.22.222"
	testDstPort           = "1234"
	testProto             = "TCP"
	testInterfaceReceived = "eth0"
	testInterfaceSent     = "eth1"
	testMacAddress        = "56:22:aa:30:c4:fe:c6:ba:6e:31:56:c9:08:00"
	testPacketTtl         = "63"
)

// Test if PacketDrop.IsExpired() works
func TestPacketDropIsExpired(t *testing.T) {
	expiredTime := util.GetExpiredTimeIn(util.DefaultPacketDropExpirationMinutes)
	expiredPacketDrop := PacketDrop{LogTime: expiredTime}
	if !expiredPacketDrop.IsExpired() {
		t.Fatal("Expected IsExpired() return true, got false")
	}

	curTime := time.Now()
	curPacketDrop := PacketDrop{LogTime: curTime}
	if curPacketDrop.IsExpired() {
		t.Fatal("Expected IsExpired() return false, got true")
	}

}

// Test if packet parser works for packet drop
func TestParsingDropLogDefaultLayout(t *testing.T) {
	parsingDropLogFmt(t, util.DefaultPacketDropLogTimeLayout)
}

func TestParsingDropLogUlogd2(t *testing.T) {
	parsingDropLogFmt(t, "Jan _2 15:04:05")
}

func parsingDropLogFmt(t *testing.T, timeLayout string) {
	channel := make(chan PacketDrop, 100)
	// need to use curTime because parse() will not insert expired packetDrop
	curTime := time.Now().Truncate(time.Second)
	logTime := curTime.Format(timeLayout)

	testLog := fmt.Sprintf("%s %s %s SRC=%s SPT=%s DST=%s DPT=%s PROTO=%s IN=%s OUT=%s MAC=%s TTL=%s", logTime, testHostname, testLogPrefix, testSrcIP, testSrcPort, testDstIP, testDstPort, testProto, testInterfaceReceived, testInterfaceSent, testMacAddress, testPacketTtl)
	expected := PacketDrop{
		LogTime:           curTime,
		HostName:          testHostname,
		SrcIP:             testSrcIP,
		SrcPort:           testSrcPort,
		DstIP:             testDstIP,
		DstPort:           testDstPort,
		Proto:             testProto,
		InterfaceReceived: testInterfaceReceived,
		InterfaceSent:     testInterfaceSent,
		MacAddress:        testMacAddress,
		Ttl:               testPacketTtl,
	}
	err := parse(testLogPrefix, testLog, channel, timeLayout)
	if err != nil {
		t.Fatalf("Expected %+v, but got error %s", expected, err)
	}

	result := <-channel
	if result != expected {
		t.Fatalf("Expected %+v, but got result %+v", expected, result)
	}
}

// Test if packet parser works for outdated packet drop (should not add it to channel)
func TestParsingExpiredPacketDropLog(t *testing.T) {
	channel := make(chan PacketDrop, 100)
	expiredTime := util.GetExpiredTimeIn(util.DefaultPacketDropExpirationMinutes).Format(util.DefaultPacketDropLogTimeLayout)
	expiredLog := fmt.Sprintf("%s %s %s SRC=%s DST=%s",
		expiredTime, testHostname, testLogPrefix, testSrcIP, testDstIP)
	parse(testLogPrefix, expiredLog, channel, util.DefaultPacketDropLogTimeLayout)

	select {
	case result := <-channel:
		t.Fatalf("expected channel empty, but got result %v", result)
	default:
		return
	}
}

// Test if packet parser works for bad packet drop (should return error)
func TestParsingBadPacketDropLog(t *testing.T) {
	channel := make(chan PacketDrop)
	// testing bad log without source IP
	curTime := time.Now().Format(util.DefaultPacketDropLogTimeLayout)
	testLog1 := fmt.Sprintf("%s %s %s %s", curTime, testHostname, testLogPrefix, testDstIP)
	err := parse(testLogPrefix, testLog1, channel, util.DefaultPacketDropLogTimeLayout)
	if err == nil {
		t.Fatalf("Expected error, but got error nil!")
	}
	// testing bad log without destination IP
	testLog2 := fmt.Sprintf("%s %s %s %s", curTime, testHostname, testLogPrefix, testSrcIP)
	err = parse(testLogPrefix, testLog2, channel, util.DefaultPacketDropLogTimeLayout)
	if err == nil {
		t.Fatalf("Expected error, but got error nil!")
	}
}

// Test if packet parser works for none packet drop log (should just ignore and not return error)
func TestParsingNonePacketDropLog(t *testing.T) {
	channel := make(chan PacketDrop)
	curTime := time.Now().Format(util.DefaultPacketDropLogTimeLayout)
	testLog := fmt.Sprintf("%s %s None Packet Drop Log", curTime, testHostname)
	err := parse(testLogPrefix, testLog, channel, util.DefaultPacketDropLogTimeLayout)

	if err != nil {
		t.Fatalf("Expected error nil, but got error %s", err)
	}
}

// Test if getPacketDropLogFields() function works
func TestGetPacketDropLogFields(t *testing.T) {
	emptyLog := " "
	_, err := getPacketDropLogFields(emptyLog, util.DefaultPacketDropLogTimeLayout)
	if err == nil {
		t.Fatalf("Expected error from empty log, but got nil")
	}

	curTime := time.Now().Format(util.DefaultPacketDropLogTimeLayout)
	// missing IPs
	packetDropLogMissingField := fmt.Sprintf("%s %s ", curTime, testHostname)
	_, err = getPacketDropLogFields(packetDropLogMissingField, util.DefaultPacketDropLogTimeLayout)
	if err == nil {
		t.Fatalf("Expected error from log %s, but got nil", packetDropLogMissingField)
	}
}
