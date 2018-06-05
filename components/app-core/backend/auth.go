package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"

	"github.com/SUSE/stratos-ui/components/app-core/backend/repository/interfaces"
	"github.com/SUSE/stratos-ui/components/app-core/backend/repository/tokens"
)

// UAAResponse - Response returned by Cloud Foundry UAA Service
type UAAResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	JTI          string `json:"jti"`
}

// LoginHookFunc - function that can be hooked into a successful user login
type LoginHookFunc func(c echo.Context) error

// UAAAdminIdentifier - The identifier that UAA uses to convey administrative level perms
const UAAAdminIdentifier = "stratos.admin"

// CFAdminIdentifier - The scope that Cloud Foundry uses to convey administrative level perms
const CFAdminIdentifier = "cloud_controller.admin"

// SessionExpiresOnHeader Custom header for communicating the session expiry time to clients
const SessionExpiresOnHeader = "X-Cap-Session-Expires-On"

// SessionExpiresAfterHeader Custom header for communicating the session expiry time to clients
const ClientRequestDateHeader = "X-Cap-Request-Date"

// EmptyCookieMatcher - Used to detect and remove empty Cookies sent by certain browsers
var EmptyCookieMatcher *regexp.Regexp = regexp.MustCompile(portalSessionName + "=(?:;[ ]*|$)")

func (p *portalProxy) getUAAIdentityEndpoint() string {
	log.Info("getUAAIdentityEndpoint")
	return fmt.Sprintf("%s/oauth/token", p.Config.ConsoleConfig.UAAEndpoint)
}

func (p *portalProxy) removeEmptyCookie(c echo.Context) {
	req := c.Request().(*standard.Request).Request
	originalCookie := req.Header.Get("Cookie")
	cleanCookie := EmptyCookieMatcher.ReplaceAllLiteralString(originalCookie, "")
	req.Header.Set("Cookie", cleanCookie)
}

// Get the user name for the specified user
func (p *portalProxy) GetUnverifiedUsername(userid string) (string, error) {
	tr, err := p.GetUAATokenRecord(userid)
	if err != nil {
		return "", err
	}

	u, userTokenErr := getUnverifiedUserTokenInfo(tr.AuthToken)
	if userTokenErr != nil {
		return "", userTokenErr
	}

	return u.UserName, nil
}

func (p *portalProxy) initSSOlogin(c echo.Context) error {
	state := c.QueryParam("state")

	redirectUrl := fmt.Sprintf("%s/oauth/authorize?%s", (&url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{p.Config.ConsoleConfig.ConsoleClient},
		"redirect_uri":  []string{getSSORedirectUri(state)},
	}).Encode())
	c.Redirect(http.StatusTemporaryRedirect, redirectUrl)
	return nil
}

func getSSORedirectUri(state string) string {
	return fmt.Sprintf("%s/pp/v1/auth/sso_login_callback?state=%s", state, url.QueryEscape(state))
}

func (p *portalProxy) loginToUAA(c echo.Context) error {
	log.Debug("loginToUAA")

	uaaRes, u, err := p.login(c, p.Config.ConsoleConfig.SkipSSLValidation, p.Config.ConsoleConfig.ConsoleClient, p.Config.ConsoleConfig.ConsoleClientSecret, p.getUAAIdentityEndpoint())
	if err != nil {
		err = interfaces.NewHTTPShadowError(
			http.StatusUnauthorized,
			"Access Denied",
			"Access Denied: %v", err)
		return err
	}

	sessionValues := make(map[string]interface{})
	sessionValues["user_id"] = u.UserGUID
	sessionValues["exp"] = u.TokenExpiry

	// Ensure that login disregards cookies from the request
	req := c.Request().(*standard.Request).Request
	req.Header.Set("Cookie", "")
	if err = p.setSessionValues(c, sessionValues); err != nil {
		return err
	}

	err = p.handleSessionExpiryHeader(c)
	if err != nil {
		return err
	}

	_, err = p.saveUAAToken(*u, uaaRes.AccessToken, uaaRes.RefreshToken)
	if err != nil {
		return err
	}

	if p.Config.LoginHook != nil {
		err = p.Config.LoginHook(c)
		if err != nil {
			log.Warn("Login hook failed", err)
		}
	}

	uaaAdmin := strings.Contains(uaaRes.Scope, p.Config.ConsoleConfig.ConsoleAdminScope)

	resp := &interfaces.LoginRes{
		Account:     u.UserName,
		TokenExpiry: u.TokenExpiry,
		APIEndpoint: nil,
		Admin:       uaaAdmin,
	}
	jsonString, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if c.Request().Method() == http.MethodGet {
		state := c.QueryParam("state")
		log.Error(state)
		return c.Redirect(http.StatusTemporaryRedirect, state)
	}

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Write(jsonString)

	return nil
}

func (p *portalProxy) loginToCNSI(c echo.Context) error {
	log.Debug("loginToCNSI")
	cnsiGuid := c.FormValue("cnsi_guid")

	resp, err := p.DoLoginToCNSI(c, cnsiGuid)
	if err != nil {
		return err
	}

	jsonString, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Write(jsonString)
	return nil
}

func (p *portalProxy) DoLoginToCNSI(c echo.Context, cnsiGUID string) (*interfaces.LoginRes, error) {
	// save the CNSI token against the Console user guid, not the CNSI user guid so that we can look it up easily
	userID, err := p.GetSessionStringValue(c, "user_id")
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Could not find correct session value")
	}

	uaaToken, err := p.GetUAATokenRecord(userID)
	if err == nil { // Found the user's UAA token
		u, err := getUnverifiedUserTokenInfo(uaaToken.AuthToken)
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusInternalServerError, "Could not parse current user UAA token")
		}

		// Save the console UAA token as the cnsi UAA token if:
		// Attempting to login to auto-registered cnsi endpoint
		// AND the auto-registered endpoint has the same UAA endpoint as console
		theCNSIrecord, _ := p.GetCNSIRecord(cnsiGUID)
		if p.GetConfig().AutoRegisterCFUrl == theCNSIrecord.APIEndpoint.String() { // CNSI API endpoint is the auto-register endpoint
			cfEndpointSpec, _ := p.GetEndpointTypeSpec("cf")
			cnsiInfo, _, err := cfEndpointSpec.Info(theCNSIrecord.APIEndpoint.String(), true)
			if err != nil {
				log.Fatal("Could not get the info for Cloud Foundry", err)
				return nil, err
			}

			uaaUrl, err := url.Parse(cnsiInfo.AuthorizationEndpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid authorization endpoint URL %s %s", cnsiInfo.AuthorizationEndpoint, err)
			}

			if uaaUrl.String() == p.GetConfig().ConsoleConfig.UAAEndpoint.String() { // CNSI UAA server matches Console UAA server
				_, err = p.saveCNSIToken(cnsiGUID, *u, uaaToken.AuthToken, uaaToken.RefreshToken, false)
				return nil, err
			} else {
				log.Info("The auto-registered endpoint UAA server does not match console UAA server.")
			}
		}
	} else {
		log.Warn("Could not find current user UAA token")
	}

	uaaRes, u, cnsiRecord, err := p.fetchToken(cnsiGUID, c)

	if err != nil {
		return nil, err
	}
	u.UserGUID = userID

	p.saveCNSIToken(cnsiGUID, *u, uaaRes.AccessToken, uaaRes.RefreshToken, false)

	cfAdmin := strings.Contains(uaaRes.Scope, p.Config.CFAdminIdentifier)

	resp := &interfaces.LoginRes{
		Account:     u.UserGUID,
		TokenExpiry: u.TokenExpiry,
		APIEndpoint: cnsiRecord.APIEndpoint,
		Admin:       cfAdmin,
	}

	return resp, nil
}

func (p *portalProxy) verifyLoginToCNSI(c echo.Context) error {
	log.Debug("verifyLoginToCNSI")

	cnsiGUID := c.FormValue("cnsi_guid")
	_, _, _, err := p.fetchToken(cnsiGUID, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}
	return c.NoContent(http.StatusOK)
}

func (p *portalProxy) fetchToken(cnsiGUID string, c echo.Context) (*UAAResponse, *userTokenInfo, *interfaces.CNSIRecord, error) {

	if len(cnsiGUID) == 0 {
		return nil, nil, nil, interfaces.NewHTTPShadowError(
			http.StatusBadRequest,
			"Missing target endpoint",
			"Need CNSI GUID passed as form param")
	}

	endpoint := ""
	cnsiRecord, err := p.GetCNSIRecord(cnsiGUID)

	if err != nil {
		return nil, nil, nil, interfaces.NewHTTPShadowError(
			http.StatusBadRequest,
			"Requested endpoint not registered",
			"No CNSI registered with GUID %s: %s", cnsiGUID, err)
	}

	endpoint = cnsiRecord.AuthorizationEndpoint

	tokenEndpoint := fmt.Sprintf("%s/oauth/token", endpoint)

	clientID, err := p.GetClientId(cnsiRecord.CNSIType)
	if err != nil {
		return nil, nil, nil, interfaces.NewHTTPShadowError(
			http.StatusBadRequest,
			"Endpoint type has not been registered",
			"Endpoint type has not been registered %s: %s", cnsiRecord.CNSIType, err)
	}

	uaaRes, u, err := p.login(c, cnsiRecord.SkipSSLValidation, clientID, "", tokenEndpoint)

	if err != nil {
		return nil, nil, nil, interfaces.NewHTTPShadowError(
			http.StatusUnauthorized,
			"Login failed",
			"Login failed: %v", err)
	}
	return uaaRes, u, &cnsiRecord, nil

}

func (p *portalProxy) GetClientId(cnsiType string) (string, error) {
	plugin, err := p.GetEndpointTypeSpec(cnsiType)
	if err != nil {
		return "", errors.New("Endpoint type not registered")
	}
	return plugin.GetClientId(), nil
}

func (p *portalProxy) logoutOfCNSI(c echo.Context) error {
	log.Debug("logoutOfCNSI")

	cnsiGUID := c.FormValue("cnsi_guid")

	if len(cnsiGUID) == 0 {
		return interfaces.NewHTTPShadowError(
			http.StatusBadRequest,
			"Missing target endpoint",
			"Need CNSI GUID passed as form param")
	}

	userGUID, err := p.GetSessionStringValue(c, "user_id")
	if err != nil {
		return fmt.Errorf("Could not find correct session value: %s", err)
	}

	cnsiRecord, err := p.GetCNSIRecord(cnsiGUID)
	if err != nil {
		return fmt.Errorf("Unable to load CNSI record: %s", err)
	}

	// If cnsi is cf AND cf is auto-register only clear the entry
	if cnsiRecord.CNSIType == "cf" && p.GetConfig().AutoRegisterCFUrl == cnsiRecord.APIEndpoint.String() {
		log.Debug("Setting token record as disconnected")

		userTokenInfo := userTokenInfo{
			UserGUID: userGUID,
		}

		if _, err := p.saveCNSIToken(cnsiGUID, userTokenInfo, "cleared_token", "cleared_token", true); err != nil {
			return fmt.Errorf("Unable to clear token: %s", err)
		}
	} else {
		log.Debug("Deleting Token")
		if err := p.deleteCNSIToken(cnsiGUID, userGUID); err != nil {
			return fmt.Errorf("Unable to delete token: %s", err)
		}
	}

	return nil
}

func (p *portalProxy) RefreshUAALogin(username, password string, store bool) error {
	log.Debug("RefreshUAALogin")
	uaaRes, err := p.getUAATokenWithCreds(p.Config.ConsoleConfig.SkipSSLValidation, username, password, p.Config.ConsoleConfig.ConsoleClient, p.Config.ConsoleConfig.ConsoleClientSecret, p.getUAAIdentityEndpoint())
	if err != nil {
		return err
	}

	u, err := getUnverifiedUserTokenInfo(uaaRes.AccessToken)
	if err != nil {
		return err
	}

	if store {
		_, err = p.saveUAAToken(*u, uaaRes.AccessToken, uaaRes.RefreshToken)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *portalProxy) login(c echo.Context, skipSSLValidation bool, client string, clientSecret string, endpoint string) (uaaRes *UAAResponse, u *userTokenInfo, err error) {
	log.Debug("login")

	if c.Request().Method() == http.MethodGet {
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		uaaRes, err = p.getUAATokenWithAuthorizationCode(skipSSLValidation, code, client, clientSecret, endpoint, state)
		if err != nil {
			return nil, nil, err
		}
	} else {
		username := c.FormValue("username")
		password := c.FormValue("password")

		if len(username) == 0 || len(password) == 0 {
			return nil, nil, errors.New("Needs username and password")
		}
		uaaRes, err = p.getUAATokenWithCreds(skipSSLValidation, username, password, client, clientSecret, endpoint)
		if err != nil {
			return nil, nil, err
		}
	}

	u, err = getUnverifiedUserTokenInfo(uaaRes.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	return uaaRes, u, nil
}

func (p *portalProxy) logout(c echo.Context) error {
	log.Debug("logout")

	p.removeEmptyCookie(c)

	err := p.clearSession(c)
	if err != nil {
		log.Errorf("Unable to clear session: %v", err)
	}

	return err
}

func (p *portalProxy) getUAATokenWithAuthorizationCode(skipSSLValidation bool, code, client, clientSecret, authEndpoint string, state string) (*UAAResponse, error) {
	log.Debug("getUAATokenWithCreds")

	redirURI := getSSORedirectUri(state)
	log.Info(redirURI)

	return p.getUAAToken(url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{redirURI},
		"client_id":     []string{client},
		"client_secret": []string{clientSecret},
		"response_type": []string{"token"},
	}, skipSSLValidation, authEndpoint)
}

func (p *portalProxy) getUAATokenWithCreds(skipSSLValidation bool, username, password, client, clientSecret, authEndpoint string) (*UAAResponse, error) {
	log.Debug("getUAATokenWithCreds")

	return p.getUAAToken(url.Values{
		"grant_type":    []string{"password"},
		"username":      []string{username},
		"password":      []string{password},
		"client_id":     []string{client},
		"client_secret": []string{clientSecret},
		"response_type": []string{"token"},
	}, skipSSLValidation, authEndpoint)
}

func (p *portalProxy) getUAATokenWithRefreshToken(skipSSLValidation bool, refreshToken, client, clientSecret, authEndpoint string) (*UAAResponse, error) {
	log.Debug("getUAATokenWithRefreshToken")

	return p.getUAAToken(url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		"client_id":     []string{client},
		"client_secret": []string{clientSecret},
		"response_type": []string{"token"},
	}, skipSSLValidation, authEndpoint)
}

func (p *portalProxy) getUAAToken(body url.Values, skipSSLValidation bool, authEndpoint string) (*UAAResponse, error) {
	log.WithField("authEndpoint", authEndpoint).Debug("getUAAToken")
	req, err := http.NewRequest("POST", authEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		msg := "Failed to create request for UAA: %v"
		log.Errorf(msg, err)
		return nil, fmt.Errorf(msg, err)
	}

	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	var h http.Client
	if skipSSLValidation {
		h = httpClientSkipSSL
	} else {
		h = httpClient
	}

	res, err := h.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		log.Errorf("Error performing http request - response: %v, error: %v", res, err)
		return nil, interfaces.LogHTTPError(res, err)
	}

	defer res.Body.Close()

	var response UAAResponse

	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(&response); err != nil {
		log.Errorf("Error decoding response: %v", err)
		return nil, fmt.Errorf("getUAAToken Decode: %s", err)
	}

	return &response, nil
}

func (p *portalProxy) saveUAAToken(u userTokenInfo, authTok string, refreshTok string) (interfaces.TokenRecord, error) {
	log.Debug("saveUAAToken")

	key := u.UserGUID
	tokenRecord := interfaces.TokenRecord{
		AuthToken:    authTok,
		RefreshToken: refreshTok,
		TokenExpiry:  u.TokenExpiry,
	}

	err := p.setUAATokenRecord(key, tokenRecord)
	if err != nil {
		return tokenRecord, err
	}

	return tokenRecord, nil
}

func (p *portalProxy) saveCNSIToken(cnsiID string, u userTokenInfo, authTok string, refreshTok string, disconnect bool) (interfaces.TokenRecord, error) {
	log.Debug("saveCNSIToken")

	tokenRecord := interfaces.TokenRecord{
		AuthToken:    authTok,
		RefreshToken: refreshTok,
		TokenExpiry:  u.TokenExpiry,
		Disconnected: disconnect,
	}

	err := p.setCNSITokenRecord(cnsiID, u.UserGUID, tokenRecord)
	if err != nil {
		log.Errorf("%v", err)
		return interfaces.TokenRecord{}, err
	}

	return tokenRecord, nil
}

func (p *portalProxy) deleteCNSIToken(cnsiID string, userGUID string) error {
	log.Debug("deleteCNSIToken")

	err := p.unsetCNSITokenRecord(cnsiID, userGUID)
	if err != nil {
		log.Errorf("%v", err)
		return err
	}

	return nil
}

func (p *portalProxy) GetUAATokenRecord(userGUID string) (interfaces.TokenRecord, error) {
	log.Debug("GetUAATokenRecord")

	tokenRepo, err := tokens.NewPgsqlTokenRepository(p.DatabaseConnectionPool)
	if err != nil {
		log.Errorf("Database error getting repo for UAA token: %v", err)
		return interfaces.TokenRecord{}, err
	}

	tr, err := tokenRepo.FindUAAToken(userGUID, p.Config.EncryptionKeyInBytes)
	if err != nil {
		log.Errorf("Database error finding UAA token: %v", err)
		return interfaces.TokenRecord{}, err
	}

	return tr, nil
}

func (p *portalProxy) setUAATokenRecord(key string, t interfaces.TokenRecord) error {
	log.Debug("setUAATokenRecord")

	tokenRepo, err := tokens.NewPgsqlTokenRepository(p.DatabaseConnectionPool)
	if err != nil {
		return fmt.Errorf("Database error getting repo for UAA token: %v", err)
	}

	err = tokenRepo.SaveUAAToken(key, t, p.Config.EncryptionKeyInBytes)
	if err != nil {
		return fmt.Errorf("Database error saving UAA token: %v", err)
	}

	return nil
}

func (p *portalProxy) verifySession(c echo.Context) error {
	log.Debug("verifySession")

	sessionExpireTime, err := p.GetSessionInt64Value(c, "exp")
	if err != nil {
		msg := "Could not find session date"
		log.Error(msg)
		return echo.NewHTTPError(http.StatusForbidden, msg)
	}

	sessionUser, err := p.GetSessionStringValue(c, "user_id")
	if err != nil {
		msg := "Could not find user_id in Session"
		log.Error(msg)
		return echo.NewHTTPError(http.StatusForbidden, msg)
	}

	tr, err := p.GetUAATokenRecord(sessionUser)
	if err != nil {
		msg := fmt.Sprintf("Unable to find UAA Token: %s", err)
		log.Error(msg, err)
		return echo.NewHTTPError(http.StatusForbidden, msg)
	}

	// Check if UAA token has expired
	if time.Now().After(time.Unix(sessionExpireTime, 0)) {

		// UAA Token has expired, refresh the token, if that fails, fail the request
		uaaRes, tokenErr := p.getUAATokenWithRefreshToken(p.Config.ConsoleConfig.SkipSSLValidation, tr.RefreshToken, p.Config.ConsoleConfig.ConsoleClient, p.Config.ConsoleConfig.ConsoleClientSecret, p.getUAAIdentityEndpoint())
		if tokenErr != nil {
			msg := "Could not refresh UAA token"
			log.Error(msg, tokenErr)
			return echo.NewHTTPError(http.StatusForbidden, msg)
		}

		u, userTokenErr := getUnverifiedUserTokenInfo(uaaRes.AccessToken)
		if userTokenErr != nil {
			return userTokenErr
		}

		if _, err = p.saveUAAToken(*u, uaaRes.AccessToken, uaaRes.RefreshToken); err != nil {
			return err
		}
		sessionValues := make(map[string]interface{})
		sessionValues["user_id"] = u.UserGUID
		sessionValues["exp"] = u.TokenExpiry

		if err = p.setSessionValues(c, sessionValues); err != nil {
			return err
		}
	} else {
		// Still need to extend the expires_on of the Session
		if err = p.setSessionValues(c, nil); err != nil {
			return err
		}
	}

	err = p.handleSessionExpiryHeader(c)
	if err != nil {
		return err
	}

	info, err := p.getInfo(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	err = c.JSON(http.StatusOK, info)
	if err != nil {
		return err
	}

	return nil
}

func (p *portalProxy) handleSessionExpiryHeader(c echo.Context) error {

	// Explicitly tell the client when this session will expire. This is needed because browsers actively hide
	// the Set-Cookie header and session cookie expires_on from client side javascript
	expOn, err := p.GetSessionValue(c, "expires_on")
	if err != nil {
		msg := "Could not get session expiry"
		log.Error(msg+" - ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, msg)
	}
	c.Response().Header().Set(SessionExpiresOnHeader, strconv.FormatInt(expOn.(time.Time).Unix(), 10))

	expiry := expOn.(time.Time)
	expiryDuration := expiry.Sub(time.Now())

	// Subtract time now to get the duration add this to the time provided by the client
	if c.Request().Header().Contains(ClientRequestDateHeader) {
		clientDate := c.Request().Header().Get(ClientRequestDateHeader)
		clientDateInt, err := strconv.ParseInt(clientDate, 10, 64)
		if err == nil {
			clientDateInt += int64(expiryDuration.Seconds())
			c.Response().Header().Set(SessionExpiresOnHeader, strconv.FormatInt(clientDateInt, 10))
		}
	}

	return nil
}

func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (p *portalProxy) getUAAUser(userGUID string) (*interfaces.ConnectedUser, error) {
	log.Debug("getUAAUser")

	// get the uaa token record
	uaaTokenRecord, err := p.GetUAATokenRecord(userGUID)
	if err != nil {
		msg := "Unable to retrieve UAA token record."
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}

	// get the scope out of the JWT token data
	userTokenInfo, err := getUnverifiedUserTokenInfo(uaaTokenRecord.AuthToken)
	if err != nil {
		msg := "Unable to find scope information in the UAA Auth Token: %s"
		log.Errorf(msg, err)
		return nil, fmt.Errorf(msg, err)
	}

	// is the user a UAA admin?
	uaaAdmin := containsScope(userTokenInfo.Scope, p.Config.ConsoleConfig.ConsoleAdminScope)

	// add the uaa entry to the output
	uaaEntry := &interfaces.ConnectedUser{
		GUID:  userGUID,
		Name:  userTokenInfo.UserName,
		Admin: uaaAdmin,
	}

	return uaaEntry, nil
}

func (p *portalProxy) GetCNSIUser(cnsiGUID string, userGUID string) (*interfaces.ConnectedUser, bool) {
	log.Debug("GetCNSIUser")

	// get the uaa token record
	cfTokenRecord, ok := p.GetCNSITokenRecord(cnsiGUID, userGUID)
	if !ok {
		msg := "Unable to retrieve CNSI token record."
		log.Error(msg)
		return nil, false
	}

	// get the scope out of the JWT token data
	userTokenInfo, err := getUnverifiedUserTokenInfo(cfTokenRecord.AuthToken)
	if err != nil {
		msg := "Unable to find scope information in the CNSI UAA Auth Token: %s"
		log.Errorf(msg, err)
		return nil, false
	}

	// add the uaa entry to the output
	cnsiUser := &interfaces.ConnectedUser{
		GUID: userTokenInfo.UserGUID,
		Name: userTokenInfo.UserName,
	}

	// is the user an CF admin?
	cnsiRecord, err := p.GetCNSIRecord(cnsiGUID)
	if err != nil {
		msg := "Unable to load CNSI record: %s"
		log.Errorf(msg, err)
		return nil, false
	}
	// TODO should be an extension point
	if cnsiRecord.CNSIType == "cf" {
		cnsiUser.Admin = containsScope(userTokenInfo.Scope, p.Config.CFAdminIdentifier)
	}

	return cnsiUser, true
}

// Refresh the UAA Token for the user
func (p *portalProxy) RefreshUAAToken(userGUID string) (t interfaces.TokenRecord, err error) {
	log.Debug("RefreshUAAToken")

	userToken, err := p.GetUAATokenRecord(userGUID)
	if err != nil {
		return t, fmt.Errorf("UAA Token info could not be found for user with GUID %s", userGUID)
	}

	uaaRes, err := p.getUAATokenWithRefreshToken(p.Config.ConsoleConfig.SkipSSLValidation, userToken.RefreshToken,
		p.Config.ConsoleConfig.ConsoleClient, p.Config.ConsoleConfig.ConsoleClientSecret, p.getUAAIdentityEndpoint())
	if err != nil {
		return t, fmt.Errorf("UAA Token refresh request failed: %v", err)
	}

	u, err := getUnverifiedUserTokenInfo(uaaRes.AccessToken)
	if err != nil {
		return t, fmt.Errorf("Could not get user token info from access token")
	}

	u.UserGUID = userGUID

	t, err = p.saveUAAToken(*u, uaaRes.AccessToken, uaaRes.RefreshToken)
	if err != nil {
		return t, fmt.Errorf("Couldn't save new UAA token: %v", err)
	}

	return t, nil
}
