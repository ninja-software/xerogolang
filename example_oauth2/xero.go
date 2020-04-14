package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/XeroAPI/xerogolang"
	"github.com/XeroAPI/xerogolang/accounting"
	"github.com/markbates/goth"
)

// QueryMap helps filtering records
type QueryMap map[string]string

// Session stores data during the auth process with Xero.
type Session struct {
	*xerogolang.Session
}

// Provider stores xerogolang library Provider structure
type Provider struct {
	*xerogolang.Provider
}

// Client wraps the Xero API client
type Client struct {
	Provider *xerogolang.Provider
	Sess     goth.Session
	// Limiter  *XeroRateLimiter
}

// WrapNewOAuth2 creates a new Xero client
func WrapNewOAuth2(clientID, clientSecret, callbackURL string, scopes []string, tenantID string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, err
	}

	x := xerogolang.NewOAuth2(clientID, clientSecret, u, "private", scopes, tenantID)
	x.HTTPClient = &http.Client{Timeout: timeout}
	x.Method = "private"
	x.UserAgentString = "AAA"

	sess, err := x.BeginOAuth2("")
	if err != nil {
		return nil, err
	}

	return &Client{
		Provider: x,
		Sess:     sess,
	}, nil
}

// CustomerList will retrive list of customers (upto 100 at a time), page is the nth(100) of record, starting from page 1
func (c *Client) CustomerList(page int, qm QueryMap) ([]accounting.Contact, error) {
	var query QueryMap

	// xero start from page 1 and onwards
	if page >= 1 {
		query = QueryMap{
			"Page": strconv.Itoa(page),
		}
	}

	for k, v := range qm {
		// if page == -1, dont specify page, so get all
		if strings.ToLower(k) == "page" && page == -1 {
			continue
		}
		query[k] = v
	}

	contacts, err := accounting.FindContacts(c.Provider, c.Sess, query)
	if err != nil {
		return nil, err
	}

	return contacts.Contacts, nil
}
