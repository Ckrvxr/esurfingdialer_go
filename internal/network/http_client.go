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
	apiClient = createHTTPClient()
}

func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectCount := len(via)
			if redirectCount >= 5 {
				return fmt.Errorf("too many redirects")
			}
			area := req.Response.Header.Get("area")
			schoolID := req.Response.Header.Get("schoolid")
			domain := req.Response.Header.Get("domain")
			if area != "" {
				States.SetArea(area)
			}
			if schoolID != "" {
				States.SetSchoolID(schoolID)
			}
			if domain != "" {
				States.SetDomain(domain)
			}
			location := req.Response.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("redirect without location")
			}
			return nil
		},
	}
}

func GetAPIClient() *http.Client {
	return apiClient
}

func Post(url, data string, extraHeaders map[string]string) NetResult {
	body := strings.NewReader(data)
	h := md5.Sum([]byte(data))
	checksum := fmt.Sprintf("%x", h)

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
	if States.GetSchoolID() != "" {
		req.Header.Set("CDC-SchoolId", States.GetSchoolID())
	}
	if States.GetDomain() != "" {
		req.Header.Set("CDC-Domain", States.GetDomain())
	}
	if States.GetArea() != "" {
		req.Header.Set("CDC-Area", States.GetArea())
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return ErrorResult(err.Error())
	}
	defer resp.Body.Close()

	if !isHTTPSuccess(resp.StatusCode) {
		return ErrorResult(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrorResult(err.Error())
	}
	return SuccessResult(raw)
}

func isHTTPSuccess(code int) bool {
	return code >= 200 && code < 300
}

// CaptiveCheck performs a captive portal detection GET request
func CaptiveCheck(url string) (*http.Response, error) {
	client := createHTTPClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CCTP/android64_vpn/2093")
	req.Header.Set("Accept", "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*")
	req.Header.Set("Client-ID", States.GetClientID())
	return client.Do(req)
}
