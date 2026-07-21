package network

import (
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
			loc := resp.header["Location"]
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
	buf := make([]byte, 4096)
	pos := 0

	for {
		n, err := r.Read(buf[pos:])
		if err != nil {
			if n == 0 {
				break
			}
		}
		pos += n
		if pos >= 4 && buf[pos-4] == '\r' && buf[pos-3] == '\n' && buf[pos-2] == '\r' && buf[pos-1] == '\n' {
			break
		}
		if n == 0 || err != nil {
			break
		}
	}

	if pos == 0 {
		return nil, fmt.Errorf("empty response")
	}

	data := buf[:pos]
	headerEnd := pos
	for i := 0; i < pos-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerEnd = i
			break
		}
	}

	// status line
	firstLine := string(data[:strings.Index(string(data), "\r\n")])
	status := 0
	if parts := strings.Fields(firstLine); len(parts) >= 2 {
		status, _ = strconv.Atoi(parts[1])
	}

	// headers
	hdr := map[string]string{}
	for _, line := range strings.Split(string(data[:headerEnd]), "\r\n") {
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			hdr[strings.ToLower(k)] = v
		}
	}

	// body
	bodyStart := headerEnd + 4
	var respBody []byte

	if cl := hdr["content-length"]; cl != "" {
		need, _ := strconv.Atoi(cl)
		have := pos - bodyStart
		for have < need {
			n, err := r.Read(buf[:])
			if n > 0 {
				data = append(data, buf[:n]...)
				have += n
			}
			if err != nil {
				break
			}
		}
		respBody = data[bodyStart : bodyStart+need]
	} else if hdr["transfer-encoding"] == "chunked" {
		respBody = readChunked(data[bodyStart:], r)
	} else {
		rest, _ := io.ReadAll(r)
		respBody = append([]byte{}, data[bodyStart:]...)
		respBody = append(respBody, rest...)
	}

	return &httpResp{status: status, header: hdr, body: respBody}, nil
}

func readChunked(init []byte, r io.Reader) []byte {
	var out []byte
	data := init
	for {
		lineEnd := -1
		for i := 0; i < len(data); i++ {
			if data[i] == '\n' {
				lineEnd = i
				break
			}
		}
		if lineEnd == -1 {
			n, err := r.Read(data[len(data):cap(data)])
			if n > 0 {
				data = data[:len(data)+n]
			}
			if err != nil {
				break
			}
			continue
		}

		sizeStr := strings.TrimSpace(string(data[:lineEnd]))
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || size == 0 {
			break
		}
		data = data[lineEnd+1:]

		for len(data) < int(size)+2 {
			n, err := r.Read(data[len(data):cap(data)])
			if n > 0 {
				data = data[:len(data)+n]
			}
			if err != nil {
				break
			}
		}

		out = append(out, data[:size]...)
		data = data[size+2:]
	}
	return out
}
