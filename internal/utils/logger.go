package utils

import (
	"log"
	"time"
)

func Print(msg string) {
	log.SetFlags(0)
	log.Printf("%s %s", time.Now().Format("2006/01/02 15:04:05"), msg)
}
