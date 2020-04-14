package xerogolang

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto"

	"github.com/XeroAPI/xerogolang/auth"
	"github.com/XeroAPI/xerogolang/helpers"
	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
	"golang.org/x/oauth2"
)

var Version = "0.1.0"

var (
	requestURL      = "https://api.xero.com/oauth/RequestToken"
	authorizeURL    = "https://api.xero.com/oauth/Authorize"
	tokenURL        = "https://api.xero.com/oauth/AccessToken"
	endpointProfile = "https://api.xero.com/api.xro/2.0/"
	//userAgentString should match the name of your Application
	userAgentString = os.Getenv("XERO_USER_AGENT") + " (xerogolang 0.2.0) " + os.Getenv("XERO_KEY")
	//privateKeyFilePath is a file path to your .pem private/public key file
	//You only need this for private and partner Applications
	//more details here: https://developer.xero.com/documentation/api-guides/create-publicprivate-key
	privateKeyFilePath = os.Getenv("XERO_PRIVATE_KEY_PATH")
)

// AuthType supported oauth type
type AuthType string

// list of supported oauth type
const (
	AuthTypeOAuth1A AuthType = "oauth1a"
	AuthTypeOAuth2  AuthType = "oauth2"
)

// Provider is the implementation of `goth.Provider` for accessing Xero.
type Provider struct {
	AuthType        AuthType
	TenantID        string // pick which tenant for oauth2 to interact with
	Scopes          []string
	ClientKey       string
	Secret          string
	CallbackURL     string
	HTTPClient      *http.Client
	Method          string
	UserAgentString string
	PrivateKey      string
	debug           bool
	consumer        *oauth.Consumer
	oauth2Client    *xoauthlite.OidcClient // holds config only
	oauth2Session   *OAuth2Session
	providerName    string
	ready           bool
}

//newPublicConsumer creates a consumer capable of communicating with a Public application: https://developer.xero.com/documentation/auth-and-limits/public-applications
func (p *Provider) newPublicConsumer(authURL string) *oauth.Consumer {

	var c *oauth.Consumer

	if p.HTTPClient != nil {
		c = oauth.NewCustomHttpClientConsumer(
			p.ClientKey,
			p.Secret,
			oauth.ServiceProvider{
				RequestTokenUrl:   requestURL,
				AuthorizeTokenUrl: authURL,
				AccessTokenUrl:    tokenURL},
			p.HTTPClient,
		)
	} else {
		c = oauth.NewConsumer(
			p.ClientKey,
			p.Secret,
			oauth.ServiceProvider{
				RequestTokenUrl:   requestURL,
				AuthorizeTokenUrl: authURL,
				AccessTokenUrl:    tokenURL},
		)
	}

	c.Debug(p.debug)

	return c
}

//newPartnerConsumer creates a consumer capable of communicating with a Partner application: https://developer.xero.com/documentation/auth-and-limits/partner-applications
func (p *Provider) newPrivateOrPartnerConsumer(authURL string) *oauth.Consumer {
	block, _ := pem.Decode([]byte(p.PrivateKey))

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	var c *oauth.Consumer

	if p.HTTPClient != nil {
		c = oauth.NewCustomRSAConsumer(
			p.ClientKey,
			privateKey,
			crypto.SHA1,
			oauth.ServiceProvider{
				RequestTokenUrl:   requestURL,
				AuthorizeTokenUrl: authURL,
				AccessTokenUrl:    tokenURL},
			p.HTTPClient,
		)
	} else {
		c = oauth.NewRSAConsumer(
			p.ClientKey,
			privateKey,
			oauth.ServiceProvider{
				RequestTokenUrl:   requestURL,
				AuthorizeTokenUrl: authURL,
				AccessTokenUrl:    tokenURL},
		)
	}

	c.Debug(p.debug)

	return c
}

// New creates a new Xero provider, and sets up important connection details.
// You should always call `xero.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		AuthType:    AuthTypeOAuth1A,
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		//Method determines how you will connect to Xero.
		//Options are public, private, and partner
		//Use public if this is your first time.
		//More details here: https://developer.xero.com/documentation/getting-started/api-application-types
		Method:          os.Getenv("XERO_METHOD"),
		PrivateKey:      helpers.ReadPrivateKeyFromPath(privateKeyFilePath),
		UserAgentString: userAgentString,
		providerName:    "xero",
	}
	return p
}

// NewNoEnviro creates a new Xero provider without using the environmental set variables
// , and sets up important connection details.
// You should always call `xero.New` to get a new Provider. Never try to create
// one manually.
func NewNoEnviro(clientKey, secret, callbackURL, userAgent, xeroMethod string, privateKey []byte) *Provider {
	// Set variables without using the environment
	userAgentString = userAgent + " (xerogolang 0.2.0) " + clientKey
	privateKeyFilePath = ""

	p := &Provider{
		AuthType:    AuthTypeOAuth1A,
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		//Method determines how you will connect to Xero.
		//Options are public, private, and partner
		//Use public if this is your first time.
		//More details here: https://developer.xero.com/documentation/getting-started/api-application-types
		Method:          xeroMethod,
		PrivateKey:      string(privateKey),
		UserAgentString: userAgentString,
		providerName:    "xero",
	}
	return p
}

// NewOAuth2 creates a new Xero provider using OAuth2, and sets up important connection details.
// You should always call `xero.NewOAuth2` to get a new Provider. Never try to create
// one manually.
func NewOAuth2(clientID, clientSecret string, callbackURL *url.URL, xeroMethod string, scopes []string, tenantID string) *Provider {
	p := &Provider{
		AuthType:        AuthTypeOAuth2,
		TenantID:        tenantID,
		ClientKey:       clientID,
		Secret:          clientSecret,
		CallbackURL:     callbackURL.String(),
		Method:          xeroMethod,
		PrivateKey:      "",
		UserAgentString: userAgentString,
		providerName:    "xero",
		Scopes:          scopes,
		consumer:        &oauth.Consumer{}, // non-nil to skip
		oauth2Client: &xoauthlite.OidcClient{
			Authority:    oidc.DefaultAuthority,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       oidc.DefaultScopes,
			RedirectURL:  callbackURL,
		},
	}
	return p
}

// NewCustomHTTPClient creates a new Xero provider, with a custom http client
func NewCustomHTTPClient(clientKey, secret, callbackURL string, httpClient *http.Client) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,

		Method:          os.Getenv("XERO_METHOD"),
		PrivateKey:      helpers.ReadPrivateKeyFromPath(privateKeyFilePath),
		UserAgentString: userAgentString,
		providerName:    "xero",
		HTTPClient:      httpClient,
	}
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client does pretty much everything
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug sets the logging of the OAuth client to verbose.
func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

// BeginAuth asks Xero for an authentication end-point and a request token for a session.
// Xero does not support the "state" variable.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	if p.AuthType == AuthTypeOAuth2 {
		return p.BeginOAuth2(state)
	}

	if p.consumer == nil {
		p.initConsumer()
	}

	if p.Method == "private" {
		accessToken := &oauth.AccessToken{
			Token:  p.ClientKey,
			Secret: p.Secret,
		}
		privateSession := &Session{
			AuthURL:            authorizeURL,
			RequestToken:       nil,
			AccessToken:        accessToken,
			AccessTokenExpires: time.Now().UTC().Add(87600 * time.Hour),
		}
		return privateSession, nil
	}
	requestToken, url, err := p.consumer.GetRequestTokenAndUrl(p.CallbackURL)
	if err != nil {
		return nil, err
	}
	session := &Session{
		AuthURL:      url,
		RequestToken: requestToken,
	}
	return session, nil
}

// BeginOAuth2 asks Xero for an authentication end-point and a request token for a session.
// Xero does not support the "state" variable.
func (p *Provider) BeginOAuth2(stateX string) (goth.Session, error) {
	u, err := url.Parse(p.CallbackURL)
	if err != nil {
		return nil, err
	}

	if p.ClientKey == "" {
		return nil, fmt.Errorf("empty client id")
	}
	if p.Secret == "" {
		return nil, fmt.Errorf("empty client secret")
	}

	clientConfig := &xoauthlite.OidcClient{
		Authority:    oidc.DefaultAuthority,
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		Scopes:       p.Scopes,
		RedirectURL:  u,
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(clientConfig.Authority)
	if wellKnownErr != nil {
		return nil, wellKnownErr
	}

	// not used
	codeChallenge := ""
	codeVerifier := ""

	// build browser link
	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		return nil, stateErr
	}
	authorisationURL, err := oidc.BuildCodeAuthorisationRequest(
		*wellKnownConfig,
		clientConfig.ClientID,
		clientConfig.RedirectURL.String(),
		clientConfig.Scopes,
		state,
		codeChallenge,
	)
	if err != nil {
		return nil, err
	}
	fmt.Println("Open browser to", authorisationURL)

	// setup http server
	m := http.NewServeMux()
	s := http.Server{
		Addr:    fmt.Sprintf(":%s", u.Port()),
		Handler: m,
	}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/callback", handler(clientConfig, wellKnownConfig, codeVerifier, state, cancel))

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		err := s.Shutdown(ctx)
		if err != nil {
			log.Println(err)
		}
	}

	// // debug
	// // prepare to print to screen
	// viewModel := *gViewModel
	// viewModel.Claims = nil
	// jsonData, err := json.MarshalIndent(viewModel, "", "    ")
	// if err != nil {
	// 	log.Println("failed to parse to json format")
	// 	cancel()
	// 	return nil, err
	// }
	// log.Debug(string(jsonData))

	now := time.Now()
	session := &OAuth2Session{
		AuthURL:            wellKnownConfig.AuthorisationEndpoint,
		AccessToken:        gViewModel.AccessToken,
		AccessTokenExpires: now.Add(time.Second * 1800),
		RefreshToken: &OAuth2RefreshToken{
			String:    gViewModel.RefreshToken,
			CreatedAt: now,
		},
		IdentityToken: gViewModel.IDToken,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	return session, nil
}

//processRequest processes a request prior to it being sent to the API
func (p *Provider) processRequest(request *http.Request, session goth.Session, additionalHeaders map[string]string) ([]byte, error) {
	if p.AuthType == AuthTypeOAuth2 {
		sessOA2 := session.(*OAuth2Session)
		return p.processRequestOAuth2(request, sessOA2, additionalHeaders)
	}

	sess := session.(*Session)

	if p.consumer == nil {
		p.initConsumer()
	}

	if sess.AccessToken == nil {
		// data is not yet retrieved since accessToken is still empty
		return nil, fmt.Errorf("%s cannot process request without accessToken", p.providerName)
	}

	request.Header.Add("User-Agent", p.UserAgentString)
	for key, value := range additionalHeaders {
		request.Header.Add(key, value)
	}

	var err error
	var response *http.Response

	if p.HTTPClient == nil {

		client, _ := p.consumer.MakeHttpClient(sess.AccessToken)

		response, err = client.Do(request)

	} else {

		transport, _ := p.consumer.MakeRoundTripper(sess.AccessToken)

		response, err = transport.RoundTrip(request)
	}

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			helpers.ReaderToString(response.Body),
		)
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Could not read response: %s", err.Error())
	}
	if responseBytes == nil {
		return nil, fmt.Errorf("Received no response: %s", err.Error())
	}
	return responseBytes, nil
}

//processRequestOAuth2 processes a request prior to it being sent to the API for oauth2
func (p *Provider) processRequestOAuth2(request *http.Request, session *OAuth2Session, additionalHeaders map[string]string) ([]byte, error) {
	var err error

	err = p.initOAuth2()
	if err != nil {
		return nil, err
	}

	// TODO move away from global
	request.Header.Add("Authorization", "Bearer "+gViewModel.AccessToken)
	// TODO move away from provider? p.oauth2Session
	request.Header.Add("Xero-tenant-id", p.TenantID)

	request.Header.Add("User-Agent", p.UserAgentString)
	for key, value := range additionalHeaders {
		request.Header.Add(key, value)
	}

	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			helpers.ReaderToString(response.Body),
		)
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Could not read response: %w", err)
	}
	if responseBytes == nil {
		return nil, fmt.Errorf("Received nil response")
	}
	return responseBytes, nil
}

//Find retrieves the requested data from an endpoint to be unmarshaled into the appropriate data type
func (p *Provider) Find(session goth.Session, endpoint string, additionalHeaders map[string]string, querystringParameters map[string]string) ([]byte, error) {
	var querystring string
	if querystringParameters != nil {
		for key, value := range querystringParameters {
			escapedValue := url.QueryEscape(value)
			querystring = querystring + "&" + key + "=" + escapedValue
		}
		querystring = strings.TrimPrefix(querystring, "&")
		querystring = "?" + querystring
	}

	request, err := http.NewRequest("GET", endpointProfile+endpoint+querystring, nil)
	if err != nil {
		return nil, err
	}

	return p.processRequest(request, session, additionalHeaders)
}

//Create sends data to an endpoint and returns a response to be unmarshaled into the appropriate data type
func (p *Provider) Create(session goth.Session, endpoint string, additionalHeaders map[string]string, body []byte, querystringParameters map[string]string) ([]byte, error) {
	var querystring string
	if querystringParameters != nil {
		for key, value := range querystringParameters {
			escapedValue := url.QueryEscape(value)
			querystring = querystring + "&" + key + "=" + escapedValue
		}
		querystring = strings.TrimPrefix(querystring, "&")
		querystring = "?" + querystring
	}

	bodyReader := bytes.NewReader(body)
	request, err := http.NewRequest("PUT", endpointProfile+endpoint+querystring, bodyReader)
	if err != nil {
		return nil, err
	}

	return p.processRequest(request, session, additionalHeaders)
}

//Update sends data to an endpoint and returns a response to be unmarshaled into the appropriate data type
func (p *Provider) Update(session goth.Session, endpoint string, additionalHeaders map[string]string, body []byte, querystringParameters map[string]string) ([]byte, error) {
	var querystring string
	if querystringParameters != nil {
		for key, value := range querystringParameters {
			escapedValue := url.QueryEscape(value)
			querystring = querystring + "&" + key + "=" + escapedValue
		}
		querystring = strings.TrimPrefix(querystring, "&")
		querystring = "?" + querystring
	}

	bodyReader := bytes.NewReader(body)
	request, err := http.NewRequest("POST", endpointProfile+endpoint+querystring, bodyReader)
	if err != nil {
		return nil, err
	}

	return p.processRequest(request, session, additionalHeaders)
}

//Remove deletes the specified data from an endpoint
func (p *Provider) Remove(session goth.Session, endpoint string, additionalHeaders map[string]string) ([]byte, error) {
	request, err := http.NewRequest("DELETE", endpointProfile+endpoint, nil)
	if err != nil {
		return nil, err
	}

	return p.processRequest(request, session, additionalHeaders)
}

// TenantConnection is the singular schema of endpoint response of xero api /connections
type TenantConnection struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenantId"`
	TenantName     string `json:"tenantName"`
	TenantType     string `json:"tenantType"`
	CreatedDateUTC string `json:"createdDateUtc"`
	UpdatedDateUTC string `json:"updatedDateUtc"`
}

// TenantConnections is collection, expected response from endpoint xero api /connections
type TenantConnections []*TenantConnection

// Connections finds out tenant connections that session have access to
func (p *Provider) Connections(session goth.Session, additionalHeaders map[string]string) ([]*TenantConnection, error) {
	endpoint := "https://api.xero.com/connections"
	request, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	responseBytes, err := p.processRequest(request, session, additionalHeaders)
	if err != nil {
		return nil, err
	}

	var tconnections TenantConnections
	err = json.Unmarshal(responseBytes, &tconnections)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal response: %w", err)
	}

	return tconnections, nil
}

//Organisation is the expected response from the Organisation endpoint - this is not a complete schema
//and should only be used by FetchUser
type Organisation struct {
	// Display name of organisation shown in Xero
	Name string `json:"Name,omitempty"`

	// Organisation name shown on Reports
	LegalName string `json:"LegalName,omitempty"`

	// Organisation Type
	OrganisationType string `json:"OrganisationType,omitempty"`

	// Country code for organisation. See ISO 3166-2 Country Codes
	CountryCode string `json:"CountryCode,omitempty"`

	// A unique identifier for the organisation.
	ShortCode string `json:"ShortCode,omitempty"`
}

//OrganisationCollection is the Total response from the Xero API
type OrganisationCollection struct {
	Organisations []Organisation `json:"Organisations,omitempty"`
}

// FetchUser will go to Xero and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		Provider: p.Name(),
	}
	additionalHeaders := map[string]string{
		"Accept": "application/json",
	}
	responseBytes, err := p.Find(sess, "Organisation", additionalHeaders, nil)
	if err != nil {
		return user, err
	}
	var organisationCollection OrganisationCollection
	err = json.Unmarshal(responseBytes, &organisationCollection)
	if err != nil {
		return user, fmt.Errorf("Could not unmarshal response: %s", err.Error())
	}

	user.Name = organisationCollection.Organisations[0].Name
	user.NickName = organisationCollection.Organisations[0].LegalName
	user.Location = organisationCollection.Organisations[0].CountryCode
	user.Description = organisationCollection.Organisations[0].OrganisationType
	user.UserID = organisationCollection.Organisations[0].ShortCode

	user.AccessToken = sess.AccessToken.Token
	user.AccessTokenSecret = sess.AccessToken.Secret
	user.ExpiresAt = sess.AccessTokenExpires
	user.Email = p.Method
	return user, err
}

//RefreshOAuth1Token should be used instead of RefeshToken which is not compliant with the Oauth1.0a standard
func (p *Provider) RefreshOAuth1Token(session *Session) error {
	if p.consumer == nil {
		p.initConsumer()
	}
	if session.AccessToken == nil {
		return fmt.Errorf("Could not refresh token as last valid accessToken was not found")
	}
	newAccessToken, err := p.consumer.RefreshToken(session.AccessToken)
	if err != nil {
		return err
	}
	session.AccessToken = newAccessToken
	session.AccessTokenExpires = time.Now().UTC().Add(30 * time.Minute)
	return nil
}

//RefreshToken refresh token is not provided by the Xero Public or Private Application -
//only the Partner Application and you must use RefreshOAuth1Token instead
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is only provided by Xero for Partner Applications")
}

//RefreshTokenAvailable refresh token is not provided by the Xero Public or Private Application -
//only the Partner Application and you must use RefreshOAuth1Token instead
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

//GetSessionFromStore returns a session for a given a request and a response
//This is an exaple of how you could get a session from a store - as long as you're
//supplying a goth.Session to the interactors it will work though so feel free to use your
//own method
func (p *Provider) GetSessionFromStore(request *http.Request, response http.ResponseWriter) (goth.Session, error) {
	sessionMarshalled, _ := auth.Store.Get(request, "xero"+auth.SessionName)
	value := sessionMarshalled.Values["xero"]
	if value == nil {
		return nil, errors.New("could not find a matching session for this request")
	}
	session, err := p.UnmarshalSession(value.(string))
	if err != nil {
		return nil, errors.New("could not unmarshal session for this request")
	}
	sess := session.(*Session)
	if sess.AccessTokenExpires.Before(time.Now().UTC().Add(5 * time.Minute)) {
		if p.Method == "partner" {
			p.RefreshOAuth1Token(sess)
			sessionMarshalled.Values["xero"] = sess.Marshal()
			err = sessionMarshalled.Save(request, response)
			return session, err
		}
		return nil, errors.New("access token has expired - please reconnect")
	}
	return session, err
}

func (p *Provider) initConsumer() {
	switch p.Method {
	case "private":
		p.consumer = p.newPrivateOrPartnerConsumer(authorizeURL)
	case "public":
		p.consumer = p.newPublicConsumer(authorizeURL)
	case "partner":
		p.consumer = p.newPrivateOrPartnerConsumer(authorizeURL)
	default:
		p.consumer = p.newPublicConsumer(authorizeURL)
	}
}

func (p *Provider) initOAuth2() error {
	var _, err = oidc.GetMetadata(oidc.DefaultAuthority)
	if err != nil {
		return err
	}
	return nil
}

// Ready is the provider is authenticated and ready to process
func (p *Provider) Ready() bool {
	return p.ready
}
