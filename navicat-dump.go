package main

import (
	"fmt"
	"os"

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
	}

	host, _, _ := key.GetStringValue("Host")
	port, _, _ := key.GetIntegerValue("Port")
	user, _, _ := key.GetStringValue("UserName")
	pwd, _, _ := key.GetStringValue("Pwd")

	return Server{Name: name, KeyPath: keyPath, Host: host, Port: int(port), User: user, Pwd: pwd}
}

func main() {
	subKeys, err := registry.USERS.ReadSubKeyNames(-1)

	if err != nil {
		fmt.Println("error: error when opening registry")
		os.Exit(1)
	}

	rights := registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS
	allServers := []Server{}

	for _, subKey := range subKeys {
		keyPath := subKey + `\SOFTWARE\PremiumSoft\Navicat\Servers\`

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

	for _, server := range allServers {
		fmt.Println(server.Name, server.KeyPath, server.Pwd)
	}
}
