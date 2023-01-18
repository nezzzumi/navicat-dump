package main

import (
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/andreburgaud/crypt2go/ecb"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/sys/windows/registry"
)

type Server struct {
	Name    string
	KeyPath string

	Host string
	Port int

	User string
	Pwd  string
}

func NewServer(name string, keyPath string) Server {
	key, err := registry.OpenKey(registry.USERS, keyPath, registry.READ)

	if err != nil {
		fmt.Println("error: opening "+name, err)
		os.Exit(1)
	}

	host, _, _ := key.GetStringValue("Host")
	port, _, _ := key.GetIntegerValue("Port")
	user, _, _ := key.GetStringValue("UserName")
	pwd, _, _ := key.GetStringValue("Pwd")

	return Server{Name: name, KeyPath: keyPath, Host: host, Port: int(port), User: user, Pwd: pwd}
}

func decryptPwd(pwd string) string {
	key := "3DC5CA39"
	keyHash := sha1.Sum([]byte(key))

	rawIV := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	iv := make([]byte, len(rawIV))
	cipherKey, _ := blowfish.NewCipher(keyHash[:])

	encrypterCBC := cipher.NewCBCEncrypter(cipherKey, iv)
	encrypterCBC.CryptBlocks(iv, rawIV)

	bytesPwd, _ := hex.DecodeString(pwd)
	var pwdDecrypted string

	fullBlocksCount := len(bytesPwd) / blowfish.BlockSize

	for i := 0; i < fullBlocksCount; i++ {
		low := i * blowfish.BlockSize
		high := i*blowfish.BlockSize + blowfish.BlockSize

		block := make([]byte, blowfish.BlockSize)
		blockDecrypted := make([]byte, blowfish.BlockSize)

		copy(block, bytesPwd[low:high])

		decrypterCBC := cipher.NewCBCDecrypter(cipherKey, iv)
		decrypterCBC.CryptBlocks(blockDecrypted, block)

		for j := 0; j < len(blockDecrypted); j++ {
			pwdDecrypted += string(blockDecrypted[j])
		}

		for j := 0; j < len(block); j++ {
			iv[j] = iv[j] ^ block[j]
		}
	}

	if remainder := len(bytesPwd) % blowfish.BlockSize; remainder != 0 {
		encrypterECB := ecb.NewECBEncrypter(cipherKey)
		encrypterECB.CryptBlocks(iv, iv)

		for i := 0; i < remainder; i++ {
			pwdDecrypted += string(bytesPwd[fullBlocksCount*8+i] ^ iv[i])
		}
	}

	return pwdDecrypted
}

func main() {
	subKeys, err := registry.USERS.ReadSubKeyNames(-1)

	if err != nil {
		fmt.Println("error: error when opening registry")
		os.Exit(1)
	}

	rights := registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS
	allServers := []Server{}
	dbmsPaths := []string{
		`\SOFTWARE\PremiumSoft\Navicat\Servers\`,        // MySQL
		`\SOFTWARE\PremiumSoft\NavicatMARIADB\Servers\`, // MariaDB
		`\SOFTWARE\PremiumSoft\NavicatMONGODB\Servers\`, // MONGODB
		`\SOFTWARE\PremiumSoft\NavicatMSSQL\Servers\`,   // SQL SERVER
		`\SOFTWARE\PremiumSoft\NavicatOra\Servers\`,     // Oracle
		`\SOFTWARE\PremiumSoft\NavicatPG\Servers\`,      // PostgreSQL
		`\SOFTWARE\PremiumSoft\NavicatSQLite\Servers\`,  // SQLite
	}

	for _, dbmsPath := range dbmsPaths {
		for _, subKey := range subKeys {
			keyPath := subKey + dbmsPath

			key, err := registry.OpenKey(registry.USERS, keyPath, uint32(rights))

			if err != nil {
				continue
			}

			servers, err := key.ReadSubKeyNames(-1)

			if err != nil {
				continue
			}

			for _, serverName := range servers {
				allServers = append(allServers, NewServer(serverName, keyPath+serverName))
			}

		}
	}

	for _, server := range allServers {
		fmt.Println("Name: " + server.Name)
		fmt.Println("Host: " + server.Host)
		fmt.Println("Port: " + strconv.Itoa(server.Port))
		fmt.Println("Username: " + server.User)
		fmt.Println("Password: " + decryptPwd(server.Pwd))
		fmt.Println()
	}
}
