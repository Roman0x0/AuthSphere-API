package main

import (
	"encoding/json"
	"os"
)

type Settings struct {
	DBLogin      string
	DBPass       string
	DBConnection string
	DBName       string

	ErrorColor  string
	GreenColor  string
	YellowColor string

	ProxyCheckKey       string
	SellixWebhookSecret string
}

var (
	settings Settings
)

func LoadSettings() {
	file, _ := os.Open("settings.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	err := decoder.Decode(&settings)
	if err != nil {
		panic(err)
	}
}
