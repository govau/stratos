package main

import (
	"errors"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
)

type userTokenInfo struct {
	UserGUID    string   `json:"user_id"`
	UserName    string   `json:"user_name"`
	TokenExpiry int64    `json:"exp"`
	Scope       []string `json:"scope"`
}

// Valid required by jwt.Claims interface
func (uti *userTokenInfo) Valid() error {
	return errors.New("not valid, this should not be called")
}

func getUnverifiedUserTokenInfo(tok string) (*userTokenInfo, error) {
	log.Debug("getUserTokenInfo")

	var rv userTokenInfo
	_, _, err := (&jwt.Parser{
		SkipClaimsValidation: true,
		UseJSONNumber:        false,
		ValidMethods:         nil,
	}).ParseUnverified(tok, &rv)
	if err != nil {
		return nil, err
	}

	return &rv, nil
}
