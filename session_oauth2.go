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
func (s *OAuth2Session) Authorize(p *Provider, params goth.Params) error {
	wellKnownConfig, err := oidc.GetMetadata(oidc.DefaultAuthority)
	if err != nil {
		return err
	}

	clientConfig := p.oauth2Client

	// not used
	codeChallenge := ""
	codeVerifier := ""

	// build browser link
	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		log.Fatal(stateErr)
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
		log.Fatal(err)
	}
	fmt.Println("Open browser to", authorisationURL)

	// setup http server
	m := http.NewServeMux()
	svr := http.Server{
		Addr:    fmt.Sprintf(":%s", clientConfig.RedirectURL.Port()),
		Handler: m,
	}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/callback", handlerOAuth2(p, clientConfig, wellKnownConfig, codeVerifier, state, cancel))

	go func() {
		if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		err := svr.Shutdown(ctx)
		if err != nil {
			log.Println(err)
		}
	}

	return nil
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
