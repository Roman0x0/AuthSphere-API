package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func GetTotalUsers(apps []Application) int {
	total := 0

	for _, app := range apps {
		_ = app
		amount := 0
		total += amount
	}
	return total
}

func IsVPN(ip string) (bool, error) {
	resp, err := http.Get(fmt.Sprintf("http://proxycheck.io/v2/%s?key=%s&vpn=3", ip, settings.ProxyCheckKey))

	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	// Log the request body
	bodyString := string(body)

	if strings.Contains(bodyString, "\"vpn\": \"yes\"") {
		return true, nil
	}
	return false, nil
}

func RandomInt(n int) string {
	var letters = []rune("0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func FormatVariables(variables []Variable) string {
	var final string
	for _, variable := range variables {
		final += fmt.Sprintf("%s:%s;", variable.Variable_Secret, variable.Variable_Value)
	}
	return final
}

func UserExpired(exp_date, currentTime string) bool {
	convertedExp, err := time.Parse("01-02-2006 15:04:05", exp_date)
	if err != nil {
		return true
	}

	convertedNow, err := time.Parse("01-02-2006 15:04:05", currentTime)
	if err != nil {
		return true
	}

	diff := convertedExp.Sub(convertedNow)
	return diff <= 0
}

func GetCurrentTime() string {
	dt := time.Now()
	return dt.Format("01-02-2006 15:04:05")
}

func GetExpirationDate(licenseExp int) string {
	dt := time.Now()
	return dt.AddDate(0, 0, licenseExp).Format("01-02-2006 15:04:05")
}

func FormatTimestamp(unixTime int64) string {
	t := time.Unix(unixTime, 0)
	strDate := t.Format("01-02-2006 15:04:05")
	return strDate
}
