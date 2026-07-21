package network

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"esurfingdialer/internal/utils"
)

const (
	CaptiveURL      = "http://connect.rom.miui.com/generate_204"
	PortalStartTag  = "<!--//config.campus.js.chinatelecom.com"
	PortalEndTag    = "//config.campus.js.chinatelecom.com-->"
	UserAgent       = "CCTP/android64_vpn/2093"
	RequestAccept   = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
)

type ConnectivityStatus int

const (
	StatusSuccess ConnectivityStatus = iota
	StatusRequireAuthorization
	StatusRequestError
)

func stripCDATA(s string) string {
	if strings.HasPrefix(s, "<![CDATA[") {
		s = s[9:]
		if idx := strings.Index(s, "]]>"); idx != -1 {
			s = s[:idx]
		}
	}
	return s
}

func extractBetweenTags(content, startTag, endTag string) string {
	startIdx := strings.Index(content, startTag)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(startTag)
	endIdx := strings.Index(content[startIdx:], endTag)
	if endIdx == -1 {
		return ""
	}
	return content[startIdx : startIdx+endIdx]
}

func DetectConfig() ConnectivityStatus {
	resp, err := CaptiveCheck(CaptiveURL)
	if err != nil {
		utils.Print("🚫 Portal check failed: " + err.Error())
		return StatusRequestError
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		utils.Print("🚫 HTTP " + fmt.Sprint(resp.StatusCode))
		return StatusRequestError
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Print("🚫 Read error: " + err.Error())
		return StatusRequestError
	}

	content := string(raw)
	portalConfigXML := extractBetweenTags(content, PortalStartTag, PortalEndTag)
	if portalConfigXML == "" {
		return StatusSuccess
	}

	cfgAuthURL := extractXMLTagSimple(portalConfigXML, "auth-url")
	cfgTicketURL := extractXMLTagSimple(portalConfigXML, "ticket-url")

	States.SetAuthURL(cfgAuthURL)
	States.SetTicketURL(cfgTicketURL)

	parseFuncfg(portalConfigXML)

	if States.GetAuthURL() == "" || States.GetTicketURL() == "" {
		utils.Print("⚠️ Portal missing auth-url or ticket-url")
		return StatusRequestError
	}

	ticketURI, err := url.Parse(States.GetTicketURL())
	if err != nil {
		utils.Print("⚠️ Invalid portal URL: " + err.Error())
		return StatusRequestError
	}
	q := ticketURI.Query()
	userIP := q.Get("wlanuserip")
	acIP := q.Get("wlanacip")
	if userIP == "" || acIP == "" {
		utils.Print("⚠️ Portal config missing userIP or acIP")
		return StatusRequestError
	}
	States.SetUserIP(userIP)
	States.SetAcIP(acIP)

	utils.Print("🔑 Portal detected, authorizing")
	return StatusRequireAuthorization
}

func extractXMLTagSimple(xmlData, tag string) string {
	start := "<" + tag + ">"
	end := "</" + tag + ">"
	startIdx := strings.Index(xmlData, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)
	endIdx := strings.Index(xmlData[startIdx:], end)
	if endIdx == -1 {
		return ""
	}
	return stripCDATA(xmlData[startIdx : startIdx+endIdx])
}

func parseFuncfg(xmlData string) {
	funcfgStart := strings.Index(xmlData, "<funcfg>")
	if funcfgStart == -1 {
		return
	}
	funcfgStart += len("<funcfg>")
	funcfgEnd := strings.Index(xmlData[funcfgStart:], "</funcfg>")
	if funcfgEnd == -1 {
		return
	}
	inner := xmlData[funcfgStart : funcfgStart+funcfgEnd]
	decoder := xml.NewDecoder(strings.NewReader(inner))
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		startElem, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var enable, urlVal string
		for _, attr := range startElem.Attr {
			if attr.Name.Local == "enable" {
				enable = attr.Value
			}
			if attr.Name.Local == "url" {
				urlVal = attr.Value
			}
		}
		if enable == "1" && urlVal != "" {
			States.GetExtraCfgURL()[startElem.Name.Local] = urlVal
		}
	}
}

func CheckVerifyCodeStatus(username string) bool {
	return requestVerifyCode(username, "QueryVerificateCodeStatus", "11062000")
}

func GetVerifyCode(username string) bool {
	return requestVerifyCode(username, "QueryAuthCode", "0")
}

func requestVerifyCode(username, reqType, success string) bool {
	urlStr := States.GetExtraCfgURL()[reqType]
	if urlStr == "" {
		return false
	}

	currentTimeMillis := fmt.Sprintf("%d", timeNowMillis())
	schoolID := States.GetSchoolID()
	auth := utils.MD5Hex(schoolID + currentTimeMillis + "Eshore!@#")
	auth = strings.ToUpper(auth)

	body := fmt.Sprintf(
		`{"schoolid":"%s","username":"%s","timestamp":"%s","authenticator":"%s"}`,
		schoolID, username, currentTimeMillis, auth,
	)

	extra := map[string]string{"Accept": "okhttp/3.4.1", "Content-Type": "application/json"}
	result := Post(urlStr, body, extra)
	if !result.IsSuccess {
		return false
	}

	resultStr := string(result.Data)
	return strings.Contains(resultStr, `"rescode":"`+success+`"`)
}

func timeNowMillis() int64 {
	return time.Now().UnixMilli()
}
