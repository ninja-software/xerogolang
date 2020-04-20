package xerogolang

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/markbates/goth"
	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

// OAuth2Session stores data during the oauth2 process with Xero
type OAuth2Session struct {
	AuthURL            string
	TenantID           string
	AccessToken        string
	AccessTokenExpires time.Time
	RefreshToken       *OAuth2RefreshToken
	IdentityToken      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// OAuth2RefreshToken token to refresh AccessToken
type OAuth2RefreshToken struct {
	String           string    // token
	Used             bool      // is token used
	LastUsedAt       time.Time // last used time
	CreatedAt        time.Time // new refresh token created time
	RefresherTime    int       // how many second before token refresher
	RefresherIsAlive bool      // auto token refresher alive?
	Echo             bool      // echo events and messages for debug
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Xero provider.
func (s *OAuth2Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Xero and return the access token to be stored for future use.
func (s *OAuth2Session) Authorize(p goth.Provider, params goth.Params) (string, error) {
	return s.AccessToken, nil
}

func handlerOAuth2(p *Provider, cc *xoauthlite.OidcClient, wellKnownConfig *oidc.WellKnownConfiguration, codeVerifier, state string, cancel context.CancelFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var authorisationResponse, err = oidc.ValidateAuthorisationResponse(r.URL, state)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		viewModel, err := xoauthlite.VerifyCode(cc.ClientID, cc.ClientSecret, cc.RedirectURL.String(), *wellKnownConfig, codeVerifier, authorisationResponse.Code)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		p.ready = true
		p.SetOauth2Session(wellKnownConfig, viewModel)

		w.Write([]byte("{\"status\": \"success\"}"))
		cancel()
	}
}

// Marshal the session into a string
func (s *OAuth2Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *OAuth2Session) String() string {
	return s.Marshal()
}

// user click xero web url callback handler
func handler(cc *xoauthlite.OidcClient, wellKnownConfig *oidc.WellKnownConfiguration, codeVerifier, state string, p *Provider, cancel context.CancelFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var authorisationResponse, err = oidc.ValidateAuthorisationResponse(r.URL, state)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		gViewModel, err := xoauthlite.VerifyCode(cc.ClientID, cc.ClientSecret, cc.RedirectURL.String(), *wellKnownConfig, codeVerifier, authorisationResponse.Code)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		// save session in provider
		p.SetOauth2Session(wellKnownConfig, gViewModel)

		w.Write([]byte("{\"status\": \"success\"}"))
		cancel()
	}
}
