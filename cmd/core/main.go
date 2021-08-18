package main

import (
	"os"

	"github.com/gajananan/argocd-interlace/cmd"
	log "github.com/sirupsen/logrus"
)

const logLevelEnvKey = "ARGOCD_INTERLACE_LOG_LEVEL"

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

func init() {
	logLevelStr := os.Getenv(logLevelEnvKey)
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)
}

func main() {
	cmd.Execute()
}
