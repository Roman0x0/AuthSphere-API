package main

import (
	"database/sql"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Email        string `json:"email"`
	Active_Plan  string `json:"active_plan"`
	Group        string `json:"active_group"`
	IsVerified   int    `json:"is_verified"`
	CreatedAt    string `json:"createdAt"`
	RegisteredIP string `json:"ip_registered"`
	SubExp       string `json:"sub_exp"`
}

type Application_Log struct {
	App_Secret string `json:"app_secret"`
	LogID      string `json:"logid"`
	Time       string `json:"time"`
	Username   string `json:"username"`
	Action     string `json:"action"`
}

type Application_User struct {
	App_Secret  string `json:"app_secret"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	IP          string `json:"ip"`
	Password    string `json:"password"`
	Exp_Date    string `json:"exp_date"`
	Expired     string `json:"expired"`
	HWID        string `json:"hwid"`
	Last_Login  string `json:"last_login"`
	Created_At  string `json:"created_at"`
	Banned      string `json:"banned"`
	Variable    string `json:"var"`
	Level       string `json:"level"`
	Color       string
	ColorBanned string
}

type Application struct {
	Name                string `json:"name"`
	Secret              string `json:"secret"`
	Pub_Key             string `json:"pub_key"`
	Priv_Key            string `json:"priv_key"`
	Status              string `json:"status"`
	Owner               string `json:"owner"`
	Integrity_Check     string `json:"int_check"`
	Application_Hash    string `json:"app_hash"`
	Application_Version string `json:"app_version"`
	Update_Check        string `json:"updt_check"`
	Update_Link         string `json:"update_link"`
	AntiVPN             string `json:"antivpn"`
	Color               string
}

type License struct {
	App_Secret string `json:"app_secret"`
	License    string `json:"license"`
	Exp        string `json:"exp"`
	Level      string `json:"level"`
	Used       string `json:"used"`
	Used_By    string `json:"used_by"`
	Color      string
}

type Variable struct {
	App_Secret      string `json:"app_secret"`
	Variable_Secret string `json:"var_secret"`
	Variable_Name   string `json:"var_name"`
	Variable_Value  string `json:"var_value"`
}

type Blacklist struct {
	App_Secret     string `json:"app_secret"`
	ID             string `json:"id"`
	Blacklist_Type string `json:"type"`
	Blacklist_Data string `json:"data"`
}

var (
	DBConnect string
	DBType    = "mysql"
)

func InitDB() {
	DBConnect = settings.DBLogin + ":" + settings.DBPass + "@tcp(127.0.0.1:3306)/" + settings.DBName
}

//// API SECTION ////

func GetBlacklists(app_secret string) ([]Blacklist, error) {
	var blacklists []Blacklist
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return blacklists, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return blacklists, err
	}

	results, err := db.Query("SELECT * FROM application_blacklist WHERE app_secret = ?", app_secret)
	if err != nil {
		return blacklists, err
	}

	for results.Next() {
		var each = Blacklist{}
		err = results.Scan(&each.App_Secret, &each.ID, &each.Blacklist_Type, &each.Blacklist_Data)
		if err != nil {
			return blacklists, err
		}

		blacklists = append(blacklists, each)
	}

	return blacklists, err
}

func GetVariables(app_secret string) ([]Variable, error) {
	var variables []Variable
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return variables, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return variables, err
	}

	results, err := db.Query("SELECT * FROM application_variables WHERE app_secret = ?", app_secret)
	if err != nil {
		return variables, err
	}

	for results.Next() {
		var each = Variable{}
		err = results.Scan(&each.App_Secret, &each.Variable_Secret, &each.Variable_Name, &each.Variable_Value)
		if err != nil {
			return variables, err
		}

		variables = append(variables, each)
	}

	return variables, err
}

func GetApplicationUser(secret, username string) (Application_User, error) {
	var user Application_User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM application_users WHERE app_secret = ? AND username = ?", secret, username)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.App_Secret, &user.Username, &user.Email, &user.IP, &user.Password, &user.Exp_Date, &user.Expired, &user.HWID, &user.Last_Login, &user.Created_At, &user.Banned, &user.Variable, &user.Level)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

func UpdateUserLoginTimeAndIP(app Application, username, currentTime, currentIP string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET last_login = ?, ip = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(currentTime, currentIP, app.Secret, username)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserHWID(app Application, username, new_hwid string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE application_users SET hwid = ? WHERE app_secret = ? AND username = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(new_hwid, app.Secret, username)
	if err != nil {
		return err
	}
	return nil
}

func SetLicenseUsed(app Application, license, username string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE licenses SET used = ?, used_by = ? WHERE license = ? AND app_secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec("yes", username, license, app.Secret)
	if err != nil {
		return err
	}
	return nil
}

func GetLicense(app Application, license string) (License, error) {
	var licenseRet License
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return licenseRet, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return licenseRet, err
	}

	results, err := db.Query("SELECT * FROM licenses WHERE app_secret = ? AND license = ?", app.Secret, license)
	if err != nil {
		return licenseRet, err
	}

	for results.Next() {
		err = results.Scan(&licenseRet.App_Secret, &licenseRet.License, &licenseRet.Exp, &licenseRet.Level, &licenseRet.Used, &licenseRet.Used_By)
		if err != nil {
			return licenseRet, err
		}
	}

	return licenseRet, err
}

func LicenseExistsAndIsAvailable(app Application, license string) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return false, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return false, err
	}

	results, err := db.Query("SELECT * FROM licenses WHERE app_secret = ? AND license = ?", app.Secret, license)
	if err != nil {
		return false, err
	}

	var licenseRet = License{}
	for results.Next() {
		err = results.Scan(&licenseRet.App_Secret, &licenseRet.License, &licenseRet.Level, &licenseRet.Exp, &licenseRet.Used, &licenseRet.Used_By)
		if err != nil {
			return false, err
		}
	}

	if (License{} == licenseRet) {
		return false, nil
	}

	if licenseRet.Used == "yes" {
		return false, nil
	}

	return true, err
}

func EmailTaken(email string, app Application) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT email FROM application_users WHERE email = ? AND app_secret = ?", email, app.Secret).Scan(&email)
	if row != nil {
		return false, nil
	}

	return true, err
}

func UserExists(username string, app Application) (bool, error) {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return true, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return true, err
	}

	row := db.QueryRow("SELECT username FROM application_users WHERE username = ? AND app_secret = ?", username, app.Secret).Scan(&username)
	if row != nil {
		return false, nil
	}

	return true, err
}

func AddLog(username, user_action string, app Application) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// add log to db
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertLog *sql.Stmt
	insertLog, err = tx.Prepare("INSERT INTO application_logs (app_secret, logid, time, username, action) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertLog.Close()

	// generate random log id
	logid := RandomInt(10)
	currentTime := GetCurrentTime()

	// check if log  was added
	var result sql.Result
	result, err = insertLog.Exec(app.Secret, logid, currentTime, username, user_action)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func AddUser(app Application, username, password, license, hwid, email, ip string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// add user to db
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertApp *sql.Stmt
	insertApp, err = tx.Prepare("INSERT INTO application_users (app_secret, username, email, ip, password, exp_date, expired, hwid, last_login, created_at, banned, var, level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertApp.Close()

	// checks to set expiration

	licenseFromDB, err := GetLicense(app, license)
	if err != nil {
		return err
	}
	licenseExp, _ := strconv.Atoi(licenseFromDB.Exp)
	expirationDate := GetExpirationDate(licenseExp)

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	currentTime := GetCurrentTime()

	// check if user was added
	var result sql.Result
	result, err = insertApp.Exec(app.Secret, username, email, ip, hashedPassword, expirationDate, "0", hwid, "N/A", currentTime, "0", "", licenseFromDB.Level)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}

func UpdateApplicationStatus(secret, status string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE applications SET status = ? WHERE secret = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(status, secret)
	if err != nil {
		return err
	}
	return nil
}

func GetApplications(userid string) ([]Application, error) {
	var apps []Application
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return apps, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return apps, err
	}

	results, err := db.Query("SELECT * FROM applications WHERE owner = ?", userid)
	if err != nil {
		return apps, err
	}

	for results.Next() {
		var each = Application{}
		err = results.Scan(&each.Name, &each.Secret, &each.Pub_Key, &each.Priv_Key, &each.Status, &each.Owner, &each.Integrity_Check, &each.Application_Hash, &each.Application_Version, &each.Update_Check, &each.Update_Link, &each.AntiVPN)
		if err != nil {
			return apps, err
		}

		// Check app status and set color
		if each.Status == "active" {
			each.Color = "#d7fada"
		} else if each.Status == "paused" {
			each.Color = settings.YellowColor
		} else {
			each.Color = "tomato"
		}

		apps = append(apps, each)
	}

	return apps, err
}

func GetApplication(userid, appName string) (Application, error) {
	var app Application
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return app, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return app, err
	}

	row := db.QueryRow("SELECT * FROM applications WHERE name = ? AND owner = ?", appName, userid).Scan(&app.Name, &app.Secret, &app.Pub_Key, &app.Priv_Key, &app.Status, &app.Owner, &app.Integrity_Check, &app.Application_Hash, &app.Application_Version, &app.Update_Check, &app.Update_Link, &app.AntiVPN)
	if row != nil {
		return app, nil
	}

	return app, err
}

func GetTotalLogCount(app Application) (int64, error) {

	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	results, err := db.Query("SELECT count(*) as count_logs FROM application_logs WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}
	var count_logs int64
	for results.Next() {
		err = results.Scan(&count_logs)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_logs
	}
	return totalCount, nil
}

func GetTotalUserCountApplication(app Application) (int64, error) {
	var totalCount int64

	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return totalCount, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return totalCount, err
	}

	var results *sql.Rows
	results, err = db.Query("SELECT count(*) as count_users FROM application_users WHERE app_secret = ?", app.Secret)
	if err != nil {
		return totalCount, err
	}

	var count_users int64
	for results.Next() {
		err = results.Scan(&count_users)
		if err != nil {
			return totalCount, err
		}
		totalCount += count_users
	}
	return totalCount, nil
}

func GetUserData(username string) (User, error) {
	var user User
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return user, err
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		return user, err
	}

	results, err := db.Query("SELECT * FROM users WHERE id = ?", username)
	if err != nil {
		return user, err
	}

	for results.Next() {

		err = results.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Active_Plan, &user.Group, &user.IsVerified, &user.CreatedAt, &user.RegisteredIP, &user.SubExp)
		if err != nil {
			return user, err
		}
	}

	return user, err
}

//// SECTION FOR LICENSES ////

func CheckDBOnline() bool {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return false
	}

	defer db.Close()

	err = db.Ping()
	return err == nil
}

//// SECTION FOR PAYMENTS ////

func UpdateSubscriptionStatus(userid, status string) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	stmt, err := db.Prepare("UPDATE payments SET status = ? WHERE userid = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(status, userid)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserAccountPlan(userid, active_plan string, subscription Subscription) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// convert sub timestamp to normal time
	expiration := FormatTimestamp(int64(subscription.Data.CurrentPeriodEnd))

	stmt, err := db.Prepare("UPDATE users SET active_plan = ?, sub_exp = ? WHERE id = ?")
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(active_plan, expiration, userid)
	if err != nil {
		return err
	}
	return nil
}

func AddPaymentToDB(userid string, subscription Subscription) error {
	db, err := sql.Open(DBType, DBConnect)
	if err != nil {
		return err
	}

	defer db.Close()

	// save payment
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer tx.Rollback()

	var insertApp *sql.Stmt
	insertApp, err = tx.Prepare("INSERT INTO payments (userid, payment_id, created_at, gateway, amount, status) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
	}
	defer insertApp.Close()

	// check if payment was added
	var result sql.Result
	result, err = insertApp.Exec(userid, subscription.Data.ID, FormatTimestamp(subscription.Data.CreatedAt), subscription.Data.Gateway, subscription.Data.Invoices[0].TotalDisplay+"€", subscription.Data.Invoices[0].Status)
	aff, _ := result.RowsAffected()
	if aff == 0 {
		return err
	}
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return err
		}
		return err
	}
	return nil
}
