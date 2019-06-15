package providers

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

type OlympiaProvider struct {
	*ProviderData
}

var _ Provider = (*OlympiaProvider)(nil)

func NewOlympiaProvider(p *ProviderData) *OlympiaProvider {
	p.ProviderName = "Olympia"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "accounts.dreams",
			Path:   "/oauth2.0/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "accounts.dreams",
			Path:   "/oauth2.0/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "accounts.dreams",
			Path:   "/oauth2.0/profile",
		}
	}
	if p.Scope == "" {
		p.Scope = "read"
	}
	return &OlympiaProvider{ProviderData: p}
}

func (p *OlympiaProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	s, err = p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *OlympiaProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *OlympiaProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}
	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}
	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email
	return
}

func (p *OlympiaProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	created := time.Now()
	profile, err := p.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}
	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    &created,
		ExpiresOn:    &token.Expiry,
		Email:        profile.Email,
		User:         profile.Username,
		FullName:     profile.Name,
	}, nil
}

type olympiaUserInfo struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

func (p *OlympiaProvider) GetUserInfo(ctx context.Context, accessToken string) (*olympiaUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform user info request: %v", err)
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got %d during user info request: %s", resp.StatusCode, body)
	}

	var userInfo olympiaUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}

	return &userInfo, nil
}
