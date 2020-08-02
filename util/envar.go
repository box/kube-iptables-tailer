package util

import (
	"log"
	"os"
	"strconv"
)

// required env vars
const (
	IptablesLogPrefix = "IPTABLES_LOG_PREFIX"
	IptablesLogPath   = "IPTABLES_LOG_PATH"
	JournalDirectory  = "JOURNAL_DIRECTORY"
)

// optional env vars
const (
	KubeApiServer = "KUBE_API_SERVER" // default value is empty string

	KubeEventDisplayReason        = "KUBE_EVENT_DISPLAY_REASON"
	DefaultKubeEventDisplayReason = "PacketDrop"

	KubeEventSourceComponentName        = "KUBE_EVENT_SOURCE_COMPONENT_NAME"
	DefaultKubeEventSourceComponentName = "kube-iptables-tailer"

	MetricsServerPort        = "METRICS_SERVER_PORT"
	DefaultMetricsServerPort = 9090

	PacketDropChannelBufferSize         = "PACKET_DROP_CHANNEL_BUFFER_SIZE"
	DefaultPacketDropsChannelBufferSize = 100

	PacketDropExpirationMinutes        = "PACKET_DROP_EXPIRATION_MINUTES"
	DefaultPacketDropExpirationMinutes = 10

	RepeatedEventIntervalMinutes        = "REPEATED_EVENTS_INTERVAL_MINUTES"
	DefaultRepeatedEventIntervalMinutes = 2

	WatchLogsIntervalSeconds       = "WATCH_LOGS_INTERVAL_SECONDS"
	DefaultWatchLogsIntervalSecond = 5

	PodIdentifier        = "POD_IDENTIFIER"
	DefaultPodIdentifier = "namespace"
	PodIdentifierLabel   = "POD_IDENTIFIER_LABEL"
)

// GetRequiredEnvString returns string environment variable of the given key
func GetRequiredEnvString(key string) string {
	val := os.Getenv(key)
	if len(val) == 0 {
		log.Fatalf("Error: Missing environment variable %v", key)
	}
	return val
}

// GetRequiredEnvString returns integer environment variable of the given key or default value if key does not exist
func GetEnvIntOrDefault(key string, def int) int {
	if env := os.Getenv(key); env != "" {
		val, err := strconv.Atoi(env)
		if err != nil {
			log.Printf("Invalid value for %v: using default: %v", key, def)
			return def
		}
		return val
	}
	return def
}

// GetEnvStringOrDefault returns string environment variable of the given key or default value if key does not exist
func GetEnvStringOrDefault(key string, def string) string {
	if val := os.Getenv(key); len(val) > 0 {
		return val
	}
	return def
}
