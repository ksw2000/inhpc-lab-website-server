package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Domain        string `json:"domain"`
	Autocert      bool   `json:"autocert"`
	Certification struct {
		Crt string `json:"crt"`
		Key string `json:"key"`
	} `json:"certification"`
}

func LoadConfig() Config {
	f, err := os.Open("config/config.json")
	if err != nil {
		panic("loadConfig() fail")
	}
	defer f.Close()

	cfg := Config{}
	decoder := json.NewDecoder(f)
	decoder.Decode(&cfg)

	return cfg
}
