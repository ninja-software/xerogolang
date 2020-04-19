package main

import (
	"fmt"
	"os"
	"time"

	"github.com/markbates/goth"
)

func main() {
	clientID := os.Getenv("XERO_CLIENT_ID")
	clientSecret := os.Getenv("XERO_CLIENT_SECRET")
	tenantID := os.Getenv("XERO_TENANT_ID")
	callbackURL := os.Getenv("XERO_REDIRECT_URL")
	scopes := []string{
		"openid",
		"profile",
		"email",
		"offline_access",
		"accounting.contacts",
	}

	// wrapper
	client, err := WrapNewOAuth2(clientID, clientSecret, callbackURL, scopes, tenantID, time.Second*10)
	if err != nil {
		panic(err)
	}
	// time.Sleep(time.Second * 5)
	fmt.Println("\n------------------------------------\n")

	qm := QueryMap{}

	tenants, err := client.Provider.Connections(client.Sess.(goth.Session), qm)
	if err != nil {
		panic(err)
	}
	for i, tenant := range tenants {
		fmt.Printf("tenant %d  %+v\n\n", i, tenant)
	}

	fmt.Println("\n------------------------------------\n")

	contacts, err := client.CustomerList(1, qm)
	if err != nil {
		panic(err)
	}
	for i, contact := range contacts {
		fmt.Printf("contact %d  %+v\n\n", i, contact)
		if i >= 2 {
			break
		}
	}

	client.Provider.SetOauth2TokenRefreshRate(300)
	client.Provider.SetOauth2TokenRefreshEcho(true)

	// prevent exiting
	select {}
}
