package main

import (
	"fmt"
	"time"
)

func logMessage(severity int, message string) {
	var moment = time.Now()

	if severity <= logVerbosity {
		fmt.Printf("[%s] %02d:%02d:%02d %04d-%02d-%02d %s\n", sevMap[severity], moment.Hour(), moment.Minute(), moment.Second(), moment.Year(), moment.Month(), moment.Day(), message)
	}
}

