package drop

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/box/kube-iptables-tailer/util"
	"go.uber.org/zap"
)

const fieldSrcIP = "SRC"
const fieldSrcPort = "SPT"
const fieldDstIP = "DST"
const fieldDstPort = "DPT"
const fieldProto = "PROTO"
const fieldInterfaceSent = "OUT"
const fieldInterfaceReceived = "IN"
const fieldTtl = "TTL"
const fieldMacAddress = "MAC"

// PacketDrop is the result object parsed from single raw log containing information about an iptables packet drop.
type PacketDrop struct {
	LogTime           time.Time
	HostName          string
	SrcIP             string
	SrcPort           string
	DstIP             string
	DstPort           string
	Proto             string
	InterfaceReceived string
	InterfaceSent     string
	MacAddress        string
	Ttl               string
}

var fieldCount = reflect.ValueOf(PacketDrop{}).NumField()

func (pd *PacketDrop) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddTime("pkt_log_time", pd.LogTime)
	enc.AddString("pkt_src_ip", pd.SrcIP)
	enc.AddString("pkt_src_port", pd.SrcPort)
	enc.AddString("pkt_dst_ip", pd.DstIP)
	enc.AddString("pkt_dst_port", pd.DstPort)
	enc.AddString("pkt_proto", pd.Proto)
	enc.AddString("pkt_ttl", pd.Ttl)
	enc.AddString("pkt_mac_addr", pd.MacAddress)
	enc.AddString("pkt_interface_recv", pd.InterfaceReceived)
	enc.AddString("pkt_interface_sent", pd.InterfaceSent)
	return nil
}

// Check if PacketDrop is expired
func (pd PacketDrop) IsExpired() bool {
	logTime := pd.GetLogTime()
	curTime := time.Now()
	expiredMinutes := float64(util.GetEnvIntOrDefault(
		util.PacketDropExpirationMinutes, util.DefaultPacketDropExpirationMinutes))
	return curTime.Sub(logTime).Minutes() > expiredMinutes
}

// Get the time object of PacketDrop log time
func (pd PacketDrop) GetLogTime() time.Time {
	return pd.LogTime
}

// Parse the logs from given channel and insert objects of PacketDrop as parsing result to another channel
func RunParsing(logPrefix string, logChangeCh <-chan string, packetDropCh chan<- PacketDrop) {
	logTimeLayout := util.GetEnvStringOrDefault(util.PacketDropLogTimeLayout, util.DefaultPacketDropLogTimeLayout)
	for log := range logChangeCh {
		parseErr := parse(logPrefix, log, packetDropCh, logTimeLayout)
		if parseErr != nil {
			// report the current error log but continue the parsing process
			zap.L().Error("Cannot parse the log line",
				zap.String("log", log),
				zap.String("error", parseErr.Error()),
			)
		}
	}
}

// Parse the given log, and insert the result to PacketDrop's channel if it's not expired
func parse(logPrefix, log string, packetDropCh chan<- PacketDrop, logTimeLayout string) error {
	// only parse the required packet drop logs
	if !isRequiredPacketDropLog(logPrefix, log) {
		return nil
	}
	zap.L().Debug("Parsing new packet", zap.String("raw", log))
	// parse the log and get an object of PacketDrop as result
	packetDrop, err := getPacketDrop(log, logTimeLayout)
	if err != nil {
		return err
	}
	// only insert the packetDrop into channel if it's not expired
	if !packetDrop.IsExpired() {
		packetDropCh <- packetDrop
	}

	return nil
}

// Check if a log is a required packet drop containing the given log prefix
func isRequiredPacketDropLog(logPrefix, log string) bool {
	for _, field := range strings.Fields(log) {
		if field == logPrefix {
			return true
		}
	}
	return false
}

// Return a PacketDrop object constructed from given PacketDropLog
func getPacketDrop(packetDropLog, logTimeLayout string) (PacketDrop, error) {
	// object PacketDrop needs at least 4 different fields
	logFields, err := getPacketDropLogFields(packetDropLog, logTimeLayout)
	if err != nil {
		return PacketDrop{}, err
	}

	// get log time and host name

	logTime, err := time.Parse(logTimeLayout, logFields[0])
	if err != nil {
		return PacketDrop{}, err
	}

	//HACK: if year is not present, assume current year
	if logTime.Year() == 0 {
		logTime = time.Date(time.Now().Year(), logTime.Month(), logTime.Day(), logTime.Hour(), logTime.Minute(), logTime.Second(), logTime.Nanosecond(), time.Local)
	}

	hostName := logFields[1]

	// get src and dst IPs
	srcIP, err := getFieldValue(logFields, fieldSrcIP)
	if err != nil {
		return PacketDrop{}, err
	}
	srcPort, err := getFieldValue(logFields, fieldSrcPort)
	if err != nil {
		return PacketDrop{}, err
	}
	dstIP, err := getFieldValue(logFields, fieldDstIP)
	if err != nil {
		return PacketDrop{}, err
	}
	dstPort, err := getFieldValue(logFields, fieldDstPort)
	if err != nil {
		return PacketDrop{}, err
	}
	proto, err := getFieldValue(logFields, fieldProto)
	if err != nil {
		return PacketDrop{}, err
	}

	interfaceReceived, err := getFieldValue(logFields, fieldInterfaceReceived)
	if err != nil {
		return PacketDrop{}, err
	}
	interfaceSent, err := getFieldValue(logFields, fieldInterfaceSent)
	if err != nil {
		return PacketDrop{}, err
	}

	// Logs don't always contain the MAC field
	macAddress, _ := getFieldValue(logFields, fieldMacAddress)

	ttl, err := getFieldValue(logFields, fieldTtl)
	if err != nil {
		return PacketDrop{}, err
	}

	pd := PacketDrop{
		LogTime:           logTime,
		HostName:          hostName,
		SrcIP:             srcIP,
		SrcPort:           srcPort,
		DstIP:             dstIP,
		DstPort:           dstPort,
		Proto:             proto,
		InterfaceReceived: interfaceReceived,
		InterfaceSent:     interfaceSent,
		MacAddress:        macAddress,
		Ttl:               ttl}

	zap.L().Info("Parsed new packet", zap.String("raw", packetDropLog), zap.Object("packet_drop", &pd))

	return pd, nil
}

// Helper function to check and return fields (if there are enough of them) of given PacketDrop log
func getPacketDropLogFields(packetDropLog string, logTimeLayout string) ([]string, error) {
	// we are expecting first field to be a log time,
	timeFieldsInLayout := strings.Fields(logTimeLayout)

	// capture leading timeFieldsInLayout.num fields as a single timestamp field
	logFields := strings.Fields(packetDropLog)
	if len(logFields) == 0 {
		return []string{}, errors.New(fmt.Sprintf("Empty packet drop: log=%+v", packetDropLog))
	}

	timeField := strings.Join(logFields[:len(timeFieldsInLayout)], " ")

	otherFields := logFields[len(timeFieldsInLayout):]

	resultingFields := append([]string{timeField}, otherFields...)

	// check if the logFields contain enough information about a packet drop
	if len(resultingFields) < fieldCount {
		return []string{}, errors.New(fmt.Sprintf("Invalid packet drop: log=%+v", packetDropLog))
	}

	return resultingFields, nil
}

// Helper function to get the field from log: "... fieldName=1.1.1" returns "1.1.1"
func getFieldValue(logFields []string, fieldName string) (string, error) {
	for _, field := range logFields {
		if strings.HasPrefix(field, fieldName) {
			fieldStrs := strings.Split(field, "=")
			if len(fieldStrs) < 2 {
				return "", errors.New(fmt.Sprintf("Missing value: field=%+v", fieldName))
			}
			return fieldStrs[1], nil

		}
	}
	return "", errors.New(fmt.Sprintf("Missing field=%+v", fieldName))
}
