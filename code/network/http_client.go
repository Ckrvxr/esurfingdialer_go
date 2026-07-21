package network

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type httpResp struct {
	status int
	header map[string]string
	body   []byte
}

func Post(url, data string, extraHeaders map[string]string) NetResult {
	h := md5.Sum([]byte(data))
	checksum := fmt.Sprintf("%x", h)

	if extraHeaders == nil {
		extraHeaders = map[string]string{}
	}
	extraHeaders["CDC-Checksum"] = checksum
	if _, ok := extraHeaders["Content-Type"]; !ok {
		extraHeaders["Content-Type"] = "application/x-www-form-urlencoded"
	}

	resp, err := doRequest("POST", url, data, extraHeaders)
	if err != nil {
		return ErrorResult(err.Error())
	}
	if resp.status < 200 || resp.status >= 300 {
		return ErrorResult("HTTP " + strconv.Itoa(resp.status))
	}
	return SuccessResult(resp.body)
}

func CaptiveCheck(url string) (int, []byte, error) {
	for range 5 {
		resp, err := doRequest("GET", url, "", nil)
		if err != nil {
			return 0, nil, err
		}

		if s := resp.header["area"]; s != "" {
			States.SetArea(s)
		}
		if s := resp.header["schoolid"]; s != "" {
			States.SetSchoolID(s)
		}
		if s := resp.header["domain"]; s != "" {
			States.SetDomain(s)
		}

		if resp.status >= 300 && resp.status < 400 {
			loc := resp.header["location"]
			if loc == "" {
				return resp.status, resp.body, nil
			}
			url = loc
			continue
		}

		return resp.status, resp.body, nil
	}
	return 0, nil, fmt.Errorf("too many redirects")
}

func doRequest(method, url, body string, extra map[string]string) (*httpResp, error) {
	host, port, path := splitURL(url)

	conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: CCTP/android64_vpn/2093\r\n")
	b.WriteString("Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*\r\n")
	b.WriteString("Accept-Encoding: identity\r\n")
	b.WriteString("Connection: close\r\n")

	if v := States.GetClientID(); v != "" {
		b.WriteString("Client-ID: " + v + "\r\n")
	}
	if v := States.GetAlgoID(); v != "" {
		b.WriteString("Algo-ID: " + v + "\r\n")
	}
	if v := States.GetSchoolID(); v != "" {
		b.WriteString("CDC-SchoolId: " + v + "\r\n")
	}
	if v := States.GetDomain(); v != "" {
		b.WriteString("CDC-Domain: " + v + "\r\n")
	}
	if v := States.GetArea(); v != "" {
		b.WriteString("CDC-Area: " + v + "\r\n")
	}
	for k, v := range extra {
		b.WriteString(k + ": " + v + "\r\n")
	}
	if body != "" {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}

	return readResponse(conn)
}

func splitURL(raw string) (host, port, path string) {
	s := raw
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	host = s
	path = "/"
	if idx := strings.Index(s, "/"); idx != -1 {
		host = s[:idx]
		path = s[idx:]
	}
	port = "80"
	if idx := strings.Index(host, ":"); idx != -1 {
		port = host[idx+1:]
		host = host[:idx]
	}
	return
}

func readResponse(r io.Reader) (*httpResp, error) {
	br := bufio.NewReader(r)

	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read status line: %w", err)
	}
	status := 0
	if parts := strings.Fields(line); len(parts) >= 2 {
		status, _ = strconv.Atoi(parts[1])
	}

	hdr := map[string]string{}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			hdr[strings.ToLower(k)] = v
		}
	}

	var body []byte
	if cl := hdr["content-length"]; cl != "" {
		need, _ := strconv.Atoi(cl)
		body = make([]byte, need)
		_, err = io.ReadFull(br, body)
	} else if hdr["transfer-encoding"] == "chunked" {
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				break
			}
			size, _ := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
			if size == 0 {
				break
			}
			chunk := make([]byte, size)
			_, err = io.ReadFull(br, chunk)
			if err != nil {
				break
			}
			body = append(body, chunk...)
			br.ReadString('\n') // trailing CRLF
		}
	} else {
		body, _ = io.ReadAll(br)
	}

	return &httpResp{status: status, header: hdr, body: body}, nil
}
