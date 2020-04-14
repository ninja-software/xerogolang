package xerogolang

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/markbates/goth"
	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

// global because this is only way to handle it (for now. since channel blocks and context.WithValue doesnt mutate existing value)
var gViewModel *xoauthlite.TokenResultViewModel

// OAuth2Session stores data during the oauth2 process with Xero
type OAuth2Session struct {
	AuthURL            string
	AccessToken        string
	AccessTokenExpires time.Time
	RefreshToken       *OAuth2RefreshToken
	IdentityToken      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// OAuth2RefreshToken token to refresh AccessToken
type OAuth2RefreshToken struct {
	String    string
	Used      bool
	UsedAt    time.Time
	CreatedAt time.Time
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
	return gViewModel.AccessToken, nil
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
		now := time.Now()
		refreshToken := &OAuth2RefreshToken{
			String:    viewModel.RefreshToken,
			CreatedAt: now,
		}
		p.oauth2Session = &OAuth2Session{
			AccessToken:   viewModel.AccessToken,
			RefreshToken:  refreshToken,
			IdentityToken: viewModel.IDToken,
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		// TODO DEBUG
		// prepare to print to screen
		viewModel2 := *viewModel
		viewModel2.Claims = nil
		jsonData, jsonErr := json.MarshalIndent(viewModel2, "", "    ")
		if jsonErr != nil {
			log.Println("failed to parse to json format")
			cancel()
			return
		}
		fmt.Println(string(jsonData))

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
func handler(cc *xoauthlite.OidcClient, wellKnownConfig *oidc.WellKnownConfiguration, codeVerifier, state string, cancel context.CancelFunc) http.HandlerFunc {
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

		gViewModel, err = xoauthlite.VerifyCode(cc.ClientID, cc.ClientSecret, cc.RedirectURL.String(), *wellKnownConfig, codeVerifier, authorisationResponse.Code)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		w.Write([]byte("{\"status\": \"success\"}"))
		cancel()
	}
}
