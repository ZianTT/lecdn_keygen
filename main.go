package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/wenzhenxi/gorsa"
)

var Publickey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAim7u3o3lZpCy1uPjSCKB
F1/ompEaCvkbQvT6zp1280vphpbrXGsB033v/3dele+JW0c0bTud/fNCutLku+3u
njbUOiIg1K0W+fkQzwu/dOP5N5Sgn68qUFISREE6ALzjOEIxBdKhS317ouXzmWms
25xrf+kxSHoRaoV61zfqc1QWMtNGKKYAunuKvLwyOP0VYvgneTUGDc/ItXrMdn4e
NO/rjtMO8GmqtTyqr8UM+mK3OE7n7sTuJyMp0dcSFihxAQO4ZniGiFSNxB6dTxtk
YBJYqrWRn1vK9CO9Nh4aTgae0s2iFBlD2btOlJ2u9D2n8GyQLTmcwO0g5ICB01AT
OQIDAQAB
-----END PUBLIC KEY-----`

var Pirvatekey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCKbu7ejeVmkLLW
4+NIIoEXX+iakRoK+RtC9PrOnXbzS+mGlutcawHTfe//d16V74lbRzRtO53980K6
0uS77e6eNtQ6IiDUrRb5+RDPC7904/k3lKCfrypQUhJEQToAvOM4QjEF0qFLfXui
5fOZaazbnGt/6TFIehFqhXrXN+pzVBYy00YopgC6e4q8vDI4/RVi+Cd5NQYNz8i1
esx2fh407+uO0w7waaq1PKqvxQz6Yrc4TufuxO4nIynR1xIWKHEBA7hmeIaIVI3E
Hp1PG2RgEliqtZGfW8r0I702HhpOBp7SzaIUGUPZu06Una70PafwbJAtOZzA7SDk
gIHTUBM5AgMBAAECggEAF89MtmqhciqhF+TKSrXkjiio0Szz1b9SuQl5ud/Lfb0o
xUVf5d1hywZ2KPJXCmLQtSpiEgeW/P7CE3ACd3BNAllb10PXcbzznrr/8RyMKYas
bqrZlZ2DIZ18FtFBMK9MRXjdBatcoqdKhJIYe+J5IKyesLljCJw2MqQSpMGxSXSE
OusBgUTbJ/lrQm/aksjTIY8VGfyfYPpv3zKdcDqqtjGXirbEv8LOe1aNkkr//7kd
xFRMEUBTHZX5h8tSPfS4PEdGhIN8U1m153Zmz6dSJ71SvEsRnCOw2v47ccNO1TeJ
y0LXwYrGkmMBmhtlHGkC7zFOGCcuqOCys41mfmmRIQKBgQC8lUALMNN077Nb1hYF
SNBlbLaJ9DipJ5KP2N0/SWZOv1kvaSl42gpHmy4lrBnzRWdBQyknk5WLB1yLqOpm
rYdsF4YEToWUQlnaS9PPZaGioHHsA3/ajLjh1HkH0ghM+3+qq30U9a57R+FPUHkK
7urEHRUNAeUoEolSOKBqoKVSIwKBgQC77BUJoho2eF908gZbZAPayVQtkx5OyDgd
kj+DTOLfPyp/6QRC6DvQ4lhyR/hyrDxhfBh6pKtht9Msp6IhekbCwSrKLG8z47rm
UPMWcz0IFWVRuflCoMdRFGw+M/dDxZLJNhucdnqWfOvkzh0HC7m9qowVCFNkgm+J
K2s30Lw08wKBgQC3rgOAIuGDX0lqZL50DTT15Qpymg5qK+Ij+82bq8lbYCLk+9/q
Fy22Cx7KkLOB8JKezWSTaLtafCQW38LXmaNylALzxOt0uZ+88OhwdIQX24C6qbnp
S/Fz/LiZ9mghW0FBIeEl/hohd6Sr1Szgik7eD5mGXtctzcg07nTJBomf0wKBgDFs
/XeEKCrNbCXhBiUBYDYqH7bA7AbCiGfWsFfDYCRhg7cSvWkvlZPyBFtCbKkUfekR
74pKRz0zURp8mJr/gx70GWIFX9Yg/mZXQihUdOfsYLKnHFUW3nWHzpRprI4pp9q+
HXMAgmuUPaL3RxE0V0z4T1G01+ImoFlOjyul/epbAoGAKLX/TcbbQ//8C3H4E44x
bc9QMpj+l/4DQGbnnCH2JM4CuTX33yLsevHfO58srx7KXfLQVauZe4IE/0BRv4IM
e3tuAPwrSb2HGWL5R3DeXiAhpCrZJGKqWt1g38v0+TjeC5ejfa0SRizbovChbv9W
HmdtTxvd8LnxwwV+0BiB89Y=
-----END PRIVATE KEY-----`

func caesarEncrypt(plainText string, shift int) string {
	shift = shift % 26
	var result string
	for i := 0; i < len(plainText); i++ {
		char := plainText[i]
		if char >= 'A' && char <= 'Z' {
			char = char + byte(shift)
			if char > 'Z' {
				char = char - 26
			}
		} else if char >= 'a' && char <= 'z' {
			char = char + byte(shift)
			if char > 'z' {
				char = char - 26
			}
		}
		result += string(char)
	}
	return result
}

func caesarDecrypt(plainText string, shift int) string {
	shift = shift % 26
	var result string
	for i := 0; i < len(plainText); i++ {
		char := plainText[i]
		if char >= 'A' && char <= 'Z' {
			char = char - byte(shift)
			if char < 'A' {
				char = char + 26
			}
		} else if char >= 'a' && char <= 'z' {
			char = char - byte(shift)
			if char < 'a' {
				char = char + 26
			}
		}
		result += string(char)
	}
	return result
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func aesEncrypt(plainText, key, iv []byte) ([]byte, error) {
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Pad the plaintext to be encrypted
	plainText = pkcs7Pad(plainText, block.BlockSize())
	// Create the AES cipher block mode
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// Create a buffer to hold the ciphertext
	cipherText := make([]byte, len(plainText))
	// Encrypt the plaintext
	blockMode.CryptBlocks(cipherText, plainText)
	return cipherText, nil
}

func aesDecrypt(cipherText, key, iv []byte) ([]byte, error) {
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Create the AES cipher block mode
	blockMode := cipher.NewCBCDecrypter(block, iv)
	// Create a buffer to hold the plaintext
	plainText := make([]byte, len(cipherText))
	// Decrypt the ciphertext
	blockMode.CryptBlocks(plainText, cipherText)
	// Unpad the plaintext
	length := len(plainText)
	unpadding := int(plainText[length-1])
	plainText = plainText[:(length - unpadding)]
	return plainText, nil
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func decrypt(encryptedString string) string {
	// remove "-----BEGIN License KEY-----" and "-----END License KEY-----"
	encryptedString = strings.Replace(encryptedString, "-----BEGIN License KEY-----\n", "", -1)
	encryptedString = strings.Replace(encryptedString, "\n-----END License KEY-----", "", -1)
	// replace \n with ""
	encryptedString = strings.Replace(encryptedString, "\n", "", -1)
	var encryptedStringWithoutNewLine string = ""
	for i := 0; i < len(encryptedString); i += 48 {
		if i+48 < len(encryptedString) {
			encryptedStringWithoutNewLine += reverseString(caesarEncrypt(encryptedString[i:i+48], 11))

		} else {
			encryptedStringWithoutNewLine += reverseString(caesarEncrypt(encryptedString[i:], 11))
		}
	}
	// aes decrypt
	key := []byte("p4KyUWuo4hJGWr1c") // 16-byte key
	iv := []byte("p4KyUWuo4hJGWr1c")  // 16-byte initialization vector
	encrypted, _ := base64.StdEncoding.DecodeString(encryptedStringWithoutNewLine)
	decrypted, _ := aesDecrypt(encrypted, key, iv)
	// caesar decrypt
	caesarDecrypted := caesarEncrypt(string(decrypted), 18)
	// hex encode
	caesarDecrypted = hex.EncodeToString([]byte(caesarDecrypted))
	priDecrypt, _ := gorsa.PublicDecrypt(caesarDecrypted, Publickey)
	// decode json to obj
	var obj map[string]interface{}
	json.Unmarshal([]byte(priDecrypt), &obj)
	// {"uuid":"67a965a0-4c39-4686-bb36-e68b878c5903","app_name":"LeCDN-Master","app_id":"LeCDN-Master-2023","system_token":"3d88261b9c1787b872120f10da019554","license_code":"Y6BVU-LEZ8S-OAFIN-Z3WFD-GKOLQ","ip":"103.45.68.24","domain":"103.45.68.24","data":"eyJtYXhfbm9kZXMiOiA1fQ==","last_license_time":1692866840,"next_license_time":1722411403,"expire_time":2145916800,"license_status":"Active"}
	return fmt.Sprintf("uuid: %s\napp_name: %s\napp_id: %s\nsystem_token: %s\nlicense_code: %s\nip: %s\ndomain: %s\ndata: %s\nlast_license_time: %d\nnext_license_time: %d\nexpire_time: %d\nlicense_status: %s\n",
		obj["uuid"], obj["app_name"], obj["app_id"], obj["system_token"], obj["license_code"], obj["ip"], obj["domain"], obj["data"], obj["last_license_time"], obj["next_license_time"], obj["expire_time"], obj["license_status"])

}

func encrypt(object map[string]interface{}) string {
	// encode json to string

	jsonString, _ := json.Marshal(object)
	// encrypt json string
	encryptedString, _ := gorsa.PriKeyEncrypt(string(jsonString), Pirvatekey)

	// hex decode and base64 encode
	decodedString, _ := hex.DecodeString(encryptedString)
	encryptedString = string(decodedString)
	// caesar encrypt
	caesarEncrypted := caesarDecrypt(encryptedString, 18)
	// aes encrypt
	key := []byte("p4KyUWuo4hJGWr1c") // 16-byte key
	iv := []byte("p4KyUWuo4hJGWr1c")  // 16-byte initialization vector
	encrypted, _ := aesEncrypt([]byte(caesarEncrypted), key, iv)
	// base64 encode
	encryptedString = base64.StdEncoding.EncodeToString(encrypted)
	// add \n
	var encryptedStringWithNewLine string = ""
	for i := 0; i < len(encryptedString); i += 48 {
		if i+48 < len(encryptedString) {
			encryptedStringWithNewLine += reverseString(caesarDecrypt(encryptedString[i:i+48], 11)) + "\n"
		} else {
			encryptedStringWithNewLine += reverseString(caesarDecrypt(encryptedString[i:], 11))
		}
	}
	license := "-----BEGIN License KEY-----\n" + encryptedStringWithNewLine + "\n-----END License KEY-----"
	return license
}

func main() {
	http.HandleFunc("/authorization", handleAuthorization)
	http.HandleFunc("/ip", handleIp)
	http.ListenAndServe(":8080", nil)
}

func handleAuthorization(w http.ResponseWriter, r *http.Request) {
	//POST
	if r.Method == "POST" {
		// {
		//   "domain": "27.0.0.1",
		//   "license_code": "Y6BVU-LEZ8S-OAFIN-Z3WFD-GKOLQ",
		//   "system_token": "3d88261b9c1787b872120f10da019554"
		// }
		domain := r.FormValue("domain")
		license_code := r.FormValue("license_code")
		system_token := r.FormValue("system_token")
		data := map[string]interface{}{
			"max_nodes": 2147483647,
		}
		dataJson, _ := json.Marshal(data)
		object := map[string]interface{}{
			"uuid":              "00000000-0000-0000-0000-000000000000",
			"app_name":          "LeCDN-Master",
			"app_id":            "LeCDN-Master-2023",
			"system_token":      system_token,
			"license_code":      license_code,
			"ip":                "127.0.0.1",
			"domain":            domain,
			"data":              dataJson,
			"last_license_time": 0,
			"next_license_time": 2145916800,
			"expire_time":       2145916800,
			"license_status":    "Active",
		}
		license := encrypt(object)
		resp := map[string]interface{}{
			"code":    0,
			"message": "Cracked by @ZianTT",
			"data": map[string]interface{}{
				"result": license,
			},
			"cost":       "1ms",
			"request-id": "1",
		}
		respJson, _ := json.Marshal(resp)
		fmt.Fprintf(w, string(respJson))
	}
}

func handleIp(w http.ResponseWriter, r *http.Request) {
	ip := map[string]interface{}{
		"ip": "127.0.0.1",
	}
	resp, _ := json.Marshal(ip)
	fmt.Fprintf(w, string(resp))
}
