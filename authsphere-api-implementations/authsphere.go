package authsphere

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	r "math/rand"
	"net/http"
	"net/url"
	"os"
	osuser "os/user"
	"regexp"
	"strings"
	"time"
)

const (
	ServerOffline          = "Server is currently not responding, try again later!"
	RegisterInvalidLicense = "The license you entered is invalid or already taken!"
	RegisterInvalidDetails = "You entered an invalid username or email!"
	RegisterUsernameTaken  = "This username is already taken!"
	RegisterEmailTaken     = "This email is already taken!"
	UserExists             = "A user with this username already exists!"
	UserLicenseTaken       = "This license is already binded to another machine!"
	UserLicenseExpired     = "Your license has expired!"
	UserBanned             = "You have been banned for violating the TOS!"
	UserBlacklisted        = "Your IP/HWID has been blacklisted!"
	VPNBlocked             = "You cannot use a vpn with our service! Please disable it."
	InvalidUser            = "User doesn't exist!"
	InvalidUserCredentials = "Username or password doesn't match!"
	InvalidLoginInfo       = "Invalid login information!"
	InvalidLogInfo         = "Invalid log information!"
	LogLimitReached        = "You can only add a maximum of 50 logs as a free user, upgrade to premium to enjoy no log limits!"
	UserLimitReached       = "You can only add a maximum of 30 users as a free user, upgrade to premium to enjoy no user limits!"
	FailedToAddLog         = "Failed to add log, contact the provider!"
	InvalidApplication     = "Application could not be initialized, please check your public key, userid, app name & secret."
	ApplicationPaused      = "This application is currently under construction, please try again later!"
	NotInitialized         = "Please initialize your application first!"
	NotLoggedIn            = "Please log into your application first!"
	ApplicationDisabled    = "Application has been disabled by the provider."
	ApplicationManipulated = "File corrupted! This program has been manipulated or cracked. This file won't work anymore."

	endpoint = "" // api endpoint url https://api.authsphere.com/v1
)

var name = ""
var userid = ""
var secret = ""
var currentVersion = ""
var publicKey = ""

var initialized bool = false
var key, iv string

var Application = Application_A{}
var User = User_U{}
var Variables = make(map[string]string)

type Application_A struct {
	Application_Status  string `json:"application_status"`
	Application_Name    string `json:"application_name"`
	User_Count          string `json:"user_count"`
	Application_Version string `json:"application_version"`
	Update_URL          string `json:"update_url"`
	Application_Hash    string `json:"application_hash"`
}

type User_U struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	IP         string `json:"ip"`
	Expires    string `json:"expires"`
	HWID       string `json:"hwid"`
	Last_Login string `json:"last_login"`
	Created_At string `json:"created_at"`
	Variable   string `json:"variable"`
	Level      string `json:"level"`
}

func API(a_name string, a_userID string, a_secret string, a_currentVersion string, a_publicKey string) {
	if a_name == "" || a_userID == "" || a_secret == "" || a_currentVersion == "" || a_publicKey == "" {
		Error(InvalidApplication)
	}

	name = a_name
	userid = a_userID
	secret = a_secret
	currentVersion = a_currentVersion
	publicKey = FormatPublicKey(a_publicKey)
}

func InitApp() {
	key = RandomString(32)
	iv = RandomString(16)

	values := url.Values{}
	values.Set("action", base64.StdEncoding.EncodeToString([]byte("app_info")))
	values.Set("userid", base64.StdEncoding.EncodeToString([]byte(userid)))
	values.Set("app_name", base64.StdEncoding.EncodeToString([]byte(name)))
	values.Set("secret", aes_encrypt(secret, key, iv))
	values.Set("version", aes_encrypt(currentVersion, key, iv))
	values.Set("hash", aes_encrypt(SHA256CheckSum(CurrentFile()), key, iv))
	values.Set("key", rsa_encrypt(key, LoadPublicKey(publicKey)))
	values.Set("iv", rsa_encrypt(iv, LoadPublicKey(publicKey)))

	var raw_response = Post(values)
	var response map[string]interface{}
	err := json.Unmarshal([]byte(raw_response), &response)
	if err != nil {
		panic(err)
	}

	if response["status"] == "success" {
		Application.Application_Status = aes_decrypt(response["application_status"].(string), key, iv)
		Application.Application_Hash = aes_decrypt(response["application_hash"].(string), key, iv)
		Application.Application_Name = aes_decrypt(response["application_name"].(string), key, iv)
		Application.Application_Version = aes_decrypt(response["application_version"].(string), key, iv)
		Application.Update_URL = aes_decrypt(response["update_url"].(string), key, iv)
		Application.User_Count = aes_decrypt(response["user_count"].(string), key, iv)

		initialized = true
	} else if response["status"] == "update_available" {
		Application.Update_URL = aes_decrypt(response["update_url"].(string), key, iv)
		Application.Application_Version = aes_decrypt(response["application_version"].(string), key, iv)

		UpdateUserApplication(Application.Update_URL, Application.Application_Version)
		return
	} else if response["status"] == "invalid_hash" {
		Error(ApplicationManipulated)
		return
	} else if response["status"] == "invalid_app" {
		Error(InvalidApplication)
		return
	} else if response["status"] == "paused" {
		Error(ApplicationPaused)
		return
	} else if response["status"] == "locked" {
		Error(ApplicationDisabled)
		return
	}
}

func Login(username string, password string) bool {

	if !initialized {
		Error(NotInitialized)
		return false
	}

	if username == "" || password == "" {
		Error(InvalidLoginInfo)
		return false
	}

	key = RandomString(32)
	iv = RandomString(16)

	values := url.Values{}
	values.Set("action", base64.StdEncoding.EncodeToString([]byte("login")))
	values.Set("userid", base64.StdEncoding.EncodeToString([]byte(userid)))
	values.Set("app_name", base64.StdEncoding.EncodeToString([]byte(name)))
	values.Set("secret", aes_encrypt(secret, key, iv))
	values.Set("username", aes_encrypt(username, key, iv))
	values.Set("password", aes_encrypt(password, key, iv))
	values.Set("hwid", aes_encrypt(GetHWID(), key, iv))
	values.Set("key", rsa_encrypt(key, LoadPublicKey(publicKey)))
	values.Set("iv", rsa_encrypt(iv, LoadPublicKey(publicKey)))

	var raw_response = Post(values)

	var response map[string]interface{}
	err := json.Unmarshal([]byte(raw_response), &response)
	if err != nil {
		panic(err)
	}

	if response["status"] == "ok" {
		User.Username = aes_decrypt(response["username"].(string), key, iv)
		User.Email = aes_decrypt(response["email"].(string), key, iv)
		User.IP = aes_decrypt(response["ip"].(string), key, iv)
		User.Expires = aes_decrypt(response["expires"].(string), key, iv)
		User.HWID = aes_decrypt(response["hwid"].(string), key, iv)
		User.Last_Login = aes_decrypt(response["last_login"].(string), key, iv)
		User.Created_At = aes_decrypt(response["created_at"].(string), key, iv)
		User.Variable = aes_decrypt(response["variable"].(string), key, iv)
		User.Level = aes_decrypt(response["level"].(string), key, iv)

		app_variables := aes_decrypt(response["app_variables"].(string), key, iv)
		for _, appVariable := range strings.Split(app_variables, ";") {
			appVariableSplit := strings.Split(appVariable, ":")
			if len(appVariableSplit) == 2 {
				Variables[appVariableSplit[0]] = appVariableSplit[1]
			}
		}
		return true
	} else if response["status"] == "invalid_user" {
		Error(InvalidUserCredentials)
		return false
	} else if response["status"] == "invalid_details" {
		Error(InvalidUserCredentials)
		return false
	} else if response["status"] == "license_expired" {
		Error(UserLicenseExpired)
		return false
	} else if response["status"] == "invalid_hwid" {
		Error(UserLicenseTaken)
		return false
	} else if response["status"] == "banned" {
		Error(UserBanned)
		return false
	} else if response["status"] == "blacklisted" {
		Error(UserBlacklisted)
		return false
	} else if response["status"] == "vpn_blocked" {
		Error(VPNBlocked)
		return false
	} else {
		return false
	}
}

func Register(username string, password string, license string, email string) bool {

	if !initialized {
		Error(NotInitialized)
		return false
	}

	if username == "" || password == "" || license == "" {
		Error(InvalidLoginInfo)
		return false
	}

	key = RandomString(32)
	iv = RandomString(16)

	values := url.Values{}
	values.Set("action", base64.StdEncoding.EncodeToString([]byte("register")))
	values.Set("userid", base64.StdEncoding.EncodeToString([]byte(userid)))
	values.Set("app_name", base64.StdEncoding.EncodeToString([]byte(name)))
	values.Set("secret", aes_encrypt(secret, key, iv))
	values.Set("username", aes_encrypt(username, key, iv))
	values.Set("password", aes_encrypt(password, key, iv))
	values.Set("license", aes_encrypt(license, key, iv))
	values.Set("email", aes_encrypt(email, key, iv))
	values.Set("hwid", aes_encrypt(GetHWID(), key, iv))
	values.Set("key", rsa_encrypt(key, LoadPublicKey(publicKey)))
	values.Set("iv", rsa_encrypt(iv, LoadPublicKey(publicKey)))

	var raw_response = Post(values)

	var response map[string]interface{}
	err := json.Unmarshal([]byte(raw_response), &response)
	if err != nil {
		panic(err)
	}

	if response["status"] == "user_added" {
		return true
	} else if response["status"] == "user_limit_reached" {
		Error(UserLimitReached)
		return false
	} else if response["status"] == "invalid_details" {
		Error(RegisterInvalidDetails)
		return false
	} else if response["status"] == "email_taken" {
		Error(RegisterEmailTaken)
		return false
	} else if response["status"] == "invalid_license" {
		Error(RegisterInvalidLicense)
		return false
	} else if response["status"] == "user_already_exists" {
		Error(UserExists)
		return false
	} else if response["status"] == "blacklisted" {
		Error(UserBlacklisted)
		return false
	} else if response["status"] == "vpn_blocked" {
		Error(VPNBlocked)
		return false
	} else {
		return false
	}
}

func License(license string) bool {

	if !initialized {
		Error(NotInitialized)
		return false
	}

	if license == "" {
		Error(InvalidLoginInfo)
		return false
	}

	key = RandomString(32)
	iv = RandomString(16)

	values := url.Values{}
	values.Set("action", base64.StdEncoding.EncodeToString([]byte("license")))
	values.Set("userid", base64.StdEncoding.EncodeToString([]byte(userid)))
	values.Set("app_name", base64.StdEncoding.EncodeToString([]byte(name)))
	values.Set("secret", aes_encrypt(secret, key, iv))
	values.Set("license", aes_encrypt(license, key, iv))
	values.Set("hwid", aes_encrypt(GetHWID(), key, iv))
	values.Set("key", rsa_encrypt(key, LoadPublicKey(publicKey)))
	values.Set("iv", rsa_encrypt(iv, LoadPublicKey(publicKey)))

	var raw_response = Post(values)

	var response map[string]interface{}
	err := json.Unmarshal([]byte(raw_response), &response)
	if err != nil {
		panic(err)
	}

	if response["status"] == "ok" {

		User.Username = aes_decrypt(response["username"].(string), key, iv)
		User.Email = aes_decrypt(response["email"].(string), key, iv)
		User.IP = aes_decrypt(response["ip"].(string), key, iv)
		User.Expires = aes_decrypt(response["expires"].(string), key, iv)
		User.HWID = aes_decrypt(response["hwid"].(string), key, iv)
		User.Last_Login = aes_decrypt(response["last_login"].(string), key, iv)
		User.Created_At = aes_decrypt(response["created_at"].(string), key, iv)
		User.Variable = aes_decrypt(response["variable"].(string), key, iv)
		User.Level = aes_decrypt(response["level"].(string), key, iv)

		app_variables := aes_decrypt(response["app_variables"].(string), key, iv)
		for _, appVariable := range strings.Split(app_variables, ";") {
			appVariableSplit := strings.Split(appVariable, ":")
			if len(appVariableSplit) == 2 {
				Variables[appVariableSplit[0]] = appVariableSplit[1]
			}
		}
		return true
	} else if response["status"] == "invalid_user" {
		Error(InvalidUserCredentials)
		return false
	} else if response["status"] == "user_limit_reached" {
		Error(UserLimitReached)
		return false
	} else if response["status"] == "invalid_license" {
		Error(RegisterInvalidLicense)
		return false
	} else if response["status"] == "license_expired" {
		Error(UserLicenseExpired)
		return false
	} else if response["status"] == "invalid_hwid" {
		Error(UserLicenseTaken)
		return false
	} else if response["status"] == "banned" {
		Error(UserBanned)
		return false
	} else if response["status"] == "license_taken" {
		Error(UserLicenseTaken)
		return false
	} else if response["status"] == "blacklisted" {
		Error(UserBlacklisted)
		return false
	} else if response["status"] == "vpn_blocked" {
		Error(VPNBlocked)
		return false
	} else {
		return false
	}
}

func AddLog(username string, action string) {

	if !initialized {
		Error(NotInitialized)
	}

	if username == "" || action == "" {
		Error(InvalidLoginInfo)
	}

	key = RandomString(32)
	iv = RandomString(16)

	values := url.Values{}
	values.Set("action", base64.StdEncoding.EncodeToString([]byte("log")))
	values.Set("userid", base64.StdEncoding.EncodeToString([]byte(userid)))
	values.Set("app_name", base64.StdEncoding.EncodeToString([]byte(name)))
	values.Set("secret", aes_encrypt(secret, key, iv))
	values.Set("username", aes_encrypt(username, key, iv))
	values.Set("user_action", aes_encrypt(action, key, iv))
	values.Set("key", rsa_encrypt(key, LoadPublicKey(publicKey)))
	values.Set("iv", rsa_encrypt(iv, LoadPublicKey(publicKey)))

	var raw_response = Post(values)

	var response map[string]interface{}
	err := json.Unmarshal([]byte(raw_response), &response)
	if err != nil {
		panic(err)
	}

	if response["status"] == "log_added" {
		return
	} else if response["status"] == "failed" {
		Error(FailedToAddLog)
	} else if response["status"] == "invalid_log_info" {
		Error(InvalidLogInfo)
	} else if response["status"] == "log_limit_reached" {
		Error(LogLimitReached)
	}
}

func GetVariable(secret string) string {
	if !initialized {
		Error(NotInitialized)
	}

	if User.Username == "" || User.HWID == "" {
		Error(NotLoggedIn)
		return ""
	}

	value, exists := Variables[secret]
	if exists {
		return value
	}
	return "N/A"

}

func UpdateUserApplication(url string, version string) {
	fmt.Println("Update", version, "available! Install it now? (y/n)")
	var response string
	fmt.Scanln(&response)
	if response == "y" || response == "yes" {
		_, err := os.StartProcess(url, []string{}, &os.ProcAttr{})
		if err != nil {
			fmt.Println("Error starting process:", err)
		}
		os.Exit(0)
	} else {
		os.Exit(0)
	}
}

func GetHWID() string { // NOTE: THIS IS NOT THE BEST WAY TO GET A USERS HWID! WE RECOMMEND USING A DIFFERENT APPROACH
	name, _ := os.Hostname()
	usr, _ := osuser.Current()

	hasher := md5.New()
	hasher.Write([]byte(name + usr.Username))
	return hex.EncodeToString(hasher.Sum(nil))
}

func RandomString(n int) string {
	var letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Intn(len(letterBytes))]
	}
	return string(b)
}

func FormatPublicKey(publicKey string) string {
	finalPublicKey := "-----BEGIN PUBLIC KEY-----\n"
	re := regexp.MustCompile(`.{1,64}(?:\\s|)`)
	chunks := re.FindAllString(publicKey, -1)
	for _, chunk := range chunks {
		finalPublicKey += chunk + "\n"
	}
	finalPublicKey += "-----END PUBLIC KEY-----"
	return finalPublicKey
}

func CurrentFile() string {
	currentExecutablePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return currentExecutablePath
}

func SHA256CheckSum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		panic(err)
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func Post(values url.Values) string {
	resp, err := http.PostForm(endpoint, values)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

func rsa_encrypt(plaintext string, pub *rsa.PublicKey) string {
	plaintextBytes := []byte(plaintext)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintextBytes)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func LoadPublicKey(key string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		fmt.Println("failed to decode PEM block")
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse public key: %v", err)
		return nil
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		fmt.Println("not an RSA public key")
		return nil
	}

	return rsaPub
}

func aes_encrypt(text, encKey, iv string) string {
	bKey := []byte(encKey)
	bText := []byte(text)
	bIV := []byte(iv)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		return ""
	}

	bText = PKCS7Padding(bText, block.BlockSize())

	blockModel := cipher.NewCBCEncrypter(block, bIV[:block.BlockSize()])
	ciphertext := make([]byte, len(bText))
	blockModel.CryptBlocks(ciphertext, bText)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aes_decrypt(cipherText, encKey, iv string) string {

	bKey := []byte(encKey)
	bIV := []byte(iv)

	bCipher, _ := base64.StdEncoding.DecodeString(cipherText)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		return ""
	}

	blockModel := cipher.NewCBCDecrypter(block, bIV[:block.BlockSize()])
	plantText := make([]byte, len(bCipher))
	blockModel.CryptBlocks(plantText, bCipher)
	plantText, err = PKCS7UnPadding(plantText)
	if err != nil {
		return ""
	}
	return string(plantText)
}

func PKCS7UnPadding(plantText []byte) ([]byte, error) {
	length := len(plantText)
	if length <= 0 {
		return nil, nil
	}
	unpadding := int(plantText[length-1])
	effectiveCount := length - unpadding
	if effectiveCount <= 0 {
		return nil, nil
	}
	return plantText[:effectiveCount], nil
}

func Error(msg string) {
	fmt.Println(msg)
	os.Exit(0)
}
