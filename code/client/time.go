package client

import "time"

func timeNowUnix() int64 {
	return time.Now().UnixMilli()
}
