package client

import (
	"fmt"
	"strings"
	"time"

	"esurfingdialer/code/network"
	"esurfingdialer/code/utils"
)

type Options struct {
	LoginUser     string
	LoginPassword string
	SmsCode       string
}

type Client struct {
	options   *Options
	keepURL   string
	termURL   string
	keepRetry string
	tick      int64
}

func NewClient(opts *Options) *Client {
	return &Client{
		options:   opts,
		keepURL:   "",
		termURL:   "",
		keepRetry: "",
	}
}

func (c *Client) Run() {
	var retryCount int
	for network.States.IsRunning() {
		switch network.DetectConfig() {
		case network.StatusSuccess:
			retryCount = 0
			if !session.IsInitialized() || !network.States.IsLogged() {
				if session.IsInitialized() && !network.States.IsLogged() {
					utils.Print("🔑 Reconnecting...")
					c.authorization()
				} else {
					utils.Print("🌐 Network connected")
				}
			} else {
				if time.Now().UnixMilli()-c.tick >= c.parseRetry()*1000 {
					if err := c.heartbeat(network.States.GetTicket()); err != nil {
						utils.Print("⚠️ Heartbeat lost: " + err.Error())
						network.States.SetLogged(false)
					} else {
						c.tick = time.Now().UnixMilli()
					}
				}
			}
			time.Sleep(time.Second)
		case network.StatusRequireAuthorization:
			retryCount = 0
			network.States.SetLogged(false)
			c.authorization()
		case network.StatusRequestError:
			retryCount++
			utils.Print(fmt.Sprintf("🚫 Request error (attempt %d), retry in 5s", retryCount))
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *Client) parseRetry() int64 {
	if c.keepRetry == "" {
		return 10
	}
	v := int64(0)
	fmt.Sscanf(c.keepRetry, "%d", &v)
	if v <= 0 {
		return 10
	}
	return v
}

func (c *Client) authorization() {
	code := c.options.SmsCode
	if strings.TrimSpace(code) == "" {
		code = c.checkSMSVerify()
	}
	codeDisplay := code
	if codeDisplay == "" {
		codeDisplay = "None"
	}
	utils.Print("📱 SMS: " + codeDisplay)

	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			utils.Print(fmt.Sprintf("🔄 Auth retry %d/3...", attempt))
		}

		network.States.RefreshStates()
		utils.Print("📡 Fetching ZSM from ticket server...")
		if err := c.initSession(); err != nil {
			utils.Print("⚠️ " + err.Error())
			time.Sleep(2 * time.Second)
			continue
		}
		if !session.IsInitialized() {
			continue
		}
		utils.Print("📍 IP: " + network.States.GetUserIP() + " / AC: " + network.States.GetAcIP())

		utils.Print("🎫 Requesting ticket...")
		ticket, err := c.getTicket()
		if err != nil {
			utils.Print("⚠️ " + err.Error())
			time.Sleep(2 * time.Second)
			continue
		}
		network.States.SetTicket(ticket)
		utils.Print("🎫 Ticket: " + ticket)

		utils.Print("🔒 Sending login credentials...")
		if err := c.login(code); err != nil {
			utils.Print("⚠️ " + err.Error())
			continue
		}

		if len(c.keepURL) == 0 {
			continue
		}

		c.tick = time.Now().UnixMilli()
		network.States.SetLogged(true)
		utils.Print("✅ Login authorized")
		return
	}

	session.Free()
	utils.Print("❌ Auth failed after 3 attempts")
}

func (c *Client) checkSMSVerify() string {
	if network.CheckVerifyCodeStatus(c.options.LoginUser) && network.GetVerifyCode(c.options.LoginUser) {
		utils.Print("📱 SMS code required")
		var code string
		for {
			fmt.Print("Input Code: ")
			_, err := fmt.Scanln(&code)
			if err == nil && strings.TrimSpace(code) != "" {
				return strings.TrimSpace(code)
			}
		}
	}
	return ""
}

func (c *Client) initSession() error {
	result := network.Post(network.States.GetTicketURL(), network.States.GetAlgoID(), nil)
	if !result.IsSuccess {
		return fmt.Errorf("init session: %s", result.Error)
	}
	session.Initialize(result.Data)
	return nil
}

func (c *Client) getTicket() (string, error) {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
    <gwip>%s</gwip>
</request>`,
		network.States.GetClientID(),
		utils.GetTime(),
		hostName,
		network.States.GetUserIP(),
		network.States.GetMacAddress(),
		hostName,
		network.States.GetAcIP(),
	)

	encrypted := session.Encrypt(payload)
	result := network.Post(network.States.GetTicketURL(), encrypted, nil)
	if !result.IsSuccess {
		return "", fmt.Errorf("get ticket: %s", result.Error)
	}

	data := session.Decrypt(string(result.Data))
	return extractXMLTag(data, "ticket"), nil
}

func (c *Client) login(code string) error {
	verify := ""
	if strings.TrimSpace(code) != "" {
		verify = "<verify>" + code + "</verify>"
	}

	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <ticket>%s</ticket>
    <local-time>%s</local-time>
    <userid>%s</userid>
    <passwd>%s</passwd>
    %s
</request>`,
		network.States.GetClientID(),
		network.States.GetTicket(),
		utils.GetTime(),
		c.options.LoginUser,
		c.options.LoginPassword,
		verify,
	)

	encrypted := session.Encrypt(payload)
	result := network.Post(network.States.GetAuthURL(), encrypted, nil)
	if !result.IsSuccess {
		return fmt.Errorf("login: %s", result.Error)
	}

	data := session.Decrypt(string(result.Data))

	c.keepURL = extractXMLTag(data, "keep-url")
	c.termURL = extractXMLTag(data, "term-url")
	c.keepRetry = extractXMLTag(data, "keep-retry")

	utils.Print("🔄 Keep-alive every " + c.keepRetry + "s")
	return nil
}

func (c *Client) heartbeat(ticket string) error {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		network.States.GetClientID(),
		utils.GetTime(),
		hostName,
		network.States.GetUserIP(),
		ticket,
		network.States.GetMacAddress(),
		hostName,
	)

	encrypted := session.Encrypt(payload)
	result := network.Post(c.keepURL, encrypted, nil)
	if !result.IsSuccess {
		return fmt.Errorf("heartbeat post: %s", result.Error)
	}

	data := session.Decrypt(string(result.Data))
	c.keepRetry = extractXMLTag(data, "interval")
	utils.Print("💓 Keep-alive, next in " + c.keepRetry + "s")
	return nil
}

func (c *Client) Term() {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>CCTP/android64_vpn/2093</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		network.States.GetClientID(),
		utils.GetTime(),
		hostName,
		network.States.GetUserIP(),
		network.States.GetTicket(),
		network.States.GetMacAddress(),
		hostName,
	)

	encrypted := session.Encrypt(payload)
	result := network.Post(c.termURL, encrypted, nil)
	if !result.IsSuccess {
		utils.Print("⚠️ Term error: " + result.Error)
	}
}

func extractXMLTag(xmlData, tag string) string {
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
	val := xmlData[startIdx : startIdx+endIdx]
	if strings.HasPrefix(val, "<![CDATA[") {
		val = val[9:]
		if idx := strings.Index(val, "]]>"); idx != -1 {
			val = val[:idx]
		}
	}
	return val
}

var hostName = utils.RandomString(10)
