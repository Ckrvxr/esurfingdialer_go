package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"esurfingdialer/code/client"
	"esurfingdialer/code/network"
	"esurfingdialer/code/utils"
)

func main() {
	var cfgPath string
	user := flag.String("u", "", "Login User (Phone Number or Other)")
	password := flag.String("p", "", "Login User Password")
	smsCode := flag.String("s", "", "Pre-enter verification code")
	flag.StringVar(&cfgPath, "c", "", "Config file path (default: ~/.config/esurfingdialer_go/config.json)")
	flag.Parse()

	merged := &client.Options{}

	if cfgPath == "" {
		if def, err := utils.DefaultConfigPath(); err == nil {
			cfgPath = def
		}
	}
	if cfg, err := utils.LoadConfig(cfgPath); err == nil {
		merged.LoginUser = cfg.User
		merged.LoginPassword = cfg.Password
		merged.SmsCode = cfg.SmsCode
	}

	if *user != "" {
		merged.LoginUser = *user
	}
	if *password != "" {
		merged.LoginPassword = *password
	}
	if *smsCode != "" {
		merged.SmsCode = *smsCode
	}

	if merged.LoginUser == "" || merged.LoginPassword == "" {
		fmt.Fprintln(os.Stderr, "Usage: esurfingdialer -u <user> -p <password> [-s <sms>] [-c <config>]")
		os.Exit(1)
	}

	c := client.NewClient(merged)
	network.States.RefreshStates()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		utils.Print("👋 Shutting down...")
		if network.States.IsRunning() {
			network.States.SetRunning(false)
		}
		if client.IsSessionInitialized() {
			if network.States.IsLogged() {
				c.Term()
			}
			client.FreeSession()
		}
		os.Exit(0)
	}()

	c.Run()
}
