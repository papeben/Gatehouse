package main

import (
	"fmt"
	"time"
)

func log(severity int, message string) {
	var (
		sevMap = [6]string{"FATAL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
		moment = time.Now()
	)

	fmt.Printf("[%s] %02d:%02d:%02d %04d-%02d-%02d %s\n", sevMap[severity], moment.Hour(), moment.Minute(), moment.Second(), moment.Year(), moment.Month(), moment.Day(), message)
}
