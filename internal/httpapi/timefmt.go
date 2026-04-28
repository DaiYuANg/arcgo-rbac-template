package httpapi

import "time"

func unixMilliToRFC3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.Unix(0, ms*int64(time.Millisecond)).UTC().Format(time.RFC3339)
}

func nowUnixMilli() int64 {
	return time.Now().UTC().UnixMilli()
}

