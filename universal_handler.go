package main

import (
	"github.com/gin-gonic/gin"
)

func HandleUniversalRequest(c *gin.Context) {
	/*iv := c.PostForm("iv")

	action := c.PostForm("action")
	userid := c.PostForm("action")
	appName := c.PostForm("app_name")

	if action == "" || userid == "" || appName == "" {
		c.JSON(http.StatusOK, gin.H{
			"status": "invalid_app",
		})
		return
	}

	app, err := GetApplication(userid, appName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "invalid_app",
		})
		return
	}

	if (Application{} == app) {
		c.JSON(http.StatusOK, gin.H{
			"status": "invalid_app",
		})
		return
	}

	switch action {
	case "app_info":

		// verify secret
		secret := DecryptAES(app.Secret, iv, c.PostForm("secret"))
		if secret != app.Secret {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_app",
			})
			return
		}

		// check if application is active and only then send all the info
		if app.Status == "paused" {
			c.JSON(http.StatusOK, gin.H{
				"status": "paused",
			})
			return
		}

		if app.Status == "locked" {
			c.JSON(http.StatusOK, gin.H{
				"status": "locked",
			})
			return
		}

		if app.Integrity_Check == "1" {
			appHash := DecryptAES(app.Secret, iv, c.PostForm("hash"))
			if app.Application_Hash != appHash {
				c.JSON(http.StatusOK, gin.H{
					"status": "invalid_hash",
				})
				return
			}
		}

		if app.Update_Check == "1" {
			appVersion := DecryptAES(app.Secret, iv, c.PostForm("version"))
			if app.Application_Version != appVersion {
				c.JSON(http.StatusOK, gin.H{
					"status":              "update_available",
					"update_url":          EncryptAES(app.Secret, iv, app.Update_Link),
					"application_version": EncryptAES(app.Secret, iv, app.Application_Version),
				})
				return
			}
		}

		totalUsers, _ := GetTotalUserCountApplication(app)

		c.JSON(http.StatusOK, gin.H{
			"status":              "success",
			"application_status":  EncryptAES(app.Secret, iv, app.Status),
			"application_name":    EncryptAES(app.Secret, iv, app.Name),
			"user_count":          EncryptAES(app.Secret, iv, fmt.Sprint(totalUsers)),
			"application_version": EncryptAES(app.Secret, iv, app.Application_Version),
			"update_url":          EncryptAES(app.Secret, iv, app.Update_Link),
			"application_hash":    EncryptAES(app.Secret, iv, app.Application_Hash),
		})
	case "register":
		username := DecryptAES(app.Secret, iv, c.PostForm("username"))
		password := DecryptAES(app.Secret, iv, c.PostForm("password"))
		license := DecryptAES(app.Secret, iv, c.PostForm("license"))
		hwid := DecryptAES(app.Secret, iv, c.PostForm("hwid"))
		email := DecryptAES(app.Secret, iv, c.PostForm("email"))
		ip := c.ClientIP()

		if username == "" || password == "" || email == "" || license == "" || hwid == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_details",
			})
			return
		}

		currentUser, err := GetUserData(app.Owner)
		if err != nil {
			panic(err)
		}

		// check if premium user or not
		// if not user is allowed to have a limit of users
		if currentUser.Active_Plan == "free" {

			totalUsers, _ := GetTotalUserCountApplication(app)

			if totalUsers >= user_application_user_limit {
				c.JSON(http.StatusOK, gin.H{
					"status": "user_limit_reached",
				})
				return
			}
		}

		// if antivpn is enabled check if IP belongs to a VPN
		if app.AntiVPN == "1" {
			vpnDetected, err := IsVPN(ip)
			if err != nil {
				panic(err)
			}

			if vpnDetected {
				c.JSON(http.StatusOK, gin.H{
					"status": "vpn_blocked",
				})
				return
			}
		}

		// check if allowed
		// check if user ip or hwid is blacklisted
		blacklists, err := GetBlacklists(app.Secret)
		if err != nil {
			panic(err)
		}

		var blacklisted bool
		for _, blacklist := range blacklists {
			if blacklist.Blacklist_Type == "HWID" {
				if blacklist.Blacklist_Data == hwid {
					blacklisted = true
					break
				}
			} else if blacklist.Blacklist_Type == "IP-Address" {
				if blacklist.Blacklist_Data == ip {
					blacklisted = true
					break
				}
			}
		}

		if blacklisted {
			c.JSON(http.StatusOK, gin.H{
				"status": "blacklisted",
			})
			return
		}

		// check if user or email is taken
		userExists, err := UserExists(username, app)
		if err != nil {
			panic(err)
		}

		if userExists {
			c.JSON(http.StatusOK, gin.H{
				"status": "user_already_exists",
			})
			return
		}

		emailTaken, err := EmailTaken(email, app)
		if err != nil {
			panic(err)
		}

		if emailTaken {
			c.JSON(http.StatusOK, gin.H{
				"status": "email_taken",
			})
			return
		}

		// check if license is valid and if its used or not
		licenseExistsOrUnused, err := LicenseExistsAndIsAvailable(app, license)
		if err != nil {
			panic(err)
		}

		if !licenseExistsOrUnused {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_license",
			})
			return
		}

		userIP := c.ClientIP()

		err = AddUser(app, username, password, license, hwid, email, userIP)
		if err != nil {
			panic(err)
		}

		err = SetLicenseUsed(app, license, username)
		if err != nil {
			panic(err)
		}

		c.JSON(http.StatusAccepted, gin.H{
			"status": "user_added",
		})

	case "login":
		username := DecryptAES(app.Secret, iv, c.PostForm("username"))
		password := DecryptAES(app.Secret, iv, c.PostForm("password"))
		hwid := DecryptAES(app.Secret, iv, c.PostForm("hwid"))
		currentIP := c.ClientIP()

		if username == "" || password == "" || hwid == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_user",
			})
			return
		}

		user, err := GetApplicationUser(app.Secret, username)
		if err != nil {
			return
		}

		if (Application_User{} == user) {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_user",
			})
			return
		}

		if !ComparePassword(user.Password, password) {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_details",
			})
			return
		}

		if user.Banned == "1" {
			c.JSON(http.StatusOK, gin.H{
				"status": "banned",
			})
			return
		}

		// check if license is not the same
		if user.HWID == "N/A" { // (HWID has been reset)
			err = UpdateUserHWID(app, username, hwid)
			if err != nil {
				panic(err) // handle in logs
			}
			user.HWID = hwid
		}

		if user.HWID != hwid {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_hwid",
			})
			return
		}

		// if antivpn is enabled check if IP belongs to a VPN
		if app.AntiVPN == "1" {
			vpnDetected, err := IsVPN(currentIP)
			if err != nil {
				panic(err)
			}

			if vpnDetected {
				c.JSON(http.StatusOK, gin.H{
					"status": "vpn_blocked",
				})
				return
			}
		}

		// check if user ip or hwid is blacklisted
		blacklists, err := GetBlacklists(app.Secret)
		if err != nil {
			panic(err)
		}

		var blacklisted bool
		for _, blacklist := range blacklists {
			if blacklist.Blacklist_Type == "HWID" {
				if blacklist.Blacklist_Data == user.HWID {
					blacklisted = true
					break
				}
			} else if blacklist.Blacklist_Type == "IP-Address" {
				if blacklist.Blacklist_Data == user.IP {
					blacklisted = true
					break
				}
			}
		}

		if blacklisted {
			c.JSON(http.StatusOK, gin.H{
				"status": "blacklisted",
			})
			return
		}

		// send different status if user expired
		if UserExpired(user.Exp_Date, GetCurrentTime()) {
			c.JSON(http.StatusOK, gin.H{
				"status": "license_expired",
			})
			return
		}

		// update user last login and ip to todays time and ip
		currentTime := GetCurrentTime()

		err = UpdateUserLoginTimeAndIP(app, username, currentTime, currentIP)
		if err != nil {
			panic(err)
		}
		user.Last_Login = currentTime
		user.IP = currentIP

		application_variables, err := GetVariables(app.Secret)
		if err != nil {
			panic(err)
		}

		c.JSON(http.StatusOK, gin.H{
			"status":        "ok",
			"username":      user.Username,
			"email":         user.Email,
			"ip":            user.IP,
			"expires":       user.Exp_Date,
			"hwid":          user.HWID,
			"last_login":    user.Last_Login,
			"created_at":    user.Created_At,
			"variable":      user.Variable,
			"level":         user.Level,
			"app_variables": FormatVariables(application_variables),
		})
	case "log":
		username := DecryptAES(app.Secret, iv, c.PostForm("username"))
		user_action := DecryptAES(app.Secret, iv, c.PostForm("user_action"))

		fmt.Println(username)
		fmt.Println(user_action)

		if username == "" || user_action == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": "invalid_log_info",
			})
			return
		}

		currentUser, err := GetUserData(app.Owner)
		if err != nil {
			panic(err)
		}

		// check if premium user or not
		// if not user is allowed to create only 50 logs max
		if currentUser.Active_Plan == "free" {

			totalLogs, err := GetTotalLogCount(app)
			if err != nil {
				panic(err)
			}

			if totalLogs >= user_application_log_limit {
				c.JSON(http.StatusOK, gin.H{
					"status": "log_limit_reached",
				})
				return
			}
		}

		err = AddLog(username, user_action, app)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status": "failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "log_added",
		})
	default:
		c.JSON(http.StatusOK, gin.H{
			"status": "not_found",
		})
	}*/
}
