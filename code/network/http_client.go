package network

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var apiClient *http.Client

func init() {
	apiClient = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if v := req.Response.Header.Get("area"); v != "" {
				States.SetArea(v)
			}
			if v := req.Response.Header.Get("schoolid"); v != "" {
				States.SetSchoolID(v)
			}
			if v := req.Response.Header.Get("domain"); v != "" {
				States.SetDomain(v)
			}
			return nil
		},
	}
}

func Post(url, data string, extraHeaders map[string]string) NetResult {
	h := md5.Sum([]byte(data))
	checksum := fmt.Sprintf("%x", h)

	body := strings.NewReader(data)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return ErrorResult(err.Error())
	}

	req.Header.Set("User-Agent", "CCTP/android64_vpn/2093")
	req.Header.Set("Accept", "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*")
	req.Header.Set("CDC-Checksum", checksum)
	req.Header.Set("Client-ID", States.GetClientID())
	req.Header.Set("Algo-ID", States.GetAlgoID())

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if v := States.GetSchoolID(); v != "" {
		req.Header.Set("CDC-SchoolId", v)
	}
	if v := States.GetDomain(); v != "" {
		req.Header.Set("CDC-Domain", v)
	}
	if v := States.GetArea(); v != "" {
		req.Header.Set("CDC-Area", v)
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return ErrorResult(err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrorResult("HTTP " + fmt.Sprint(resp.StatusCode))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrorResult(err.Error())
	}
	return SuccessResult(raw)
}

func CaptiveCheck(url string) (int, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "CCTP/android64_vpn/2093")
	req.Header.Set("Accept", "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*")
	req.Header.Set("Client-ID", States.GetClientID())

	resp, err := apiClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}
