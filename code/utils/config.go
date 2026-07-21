package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	User     string `json:"user"`
	Password string `json:"password"`
	SmsCode  string `json:"sms_code,omitempty"`
}

func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "esurfingdialer_go", "config.json"), nil
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
