package auth

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"strconv"
	"time"
)

func (a *Auth) GetActionToken(userId int64, action Action) (string, error) {
	expired := time.Now().Add(time.Minute * 30).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"expire": strconv.FormatInt(expired, 10),
		"sub":    strconv.FormatInt(userId, 10),
		"action": action,
	})

	return token.SignedString([]byte(a.SecretKey))
}

func (a *Auth) CheckActionToken(tokenString string) (userId int64, action Action, err error) {
	var token *jwt.Token

	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(a.SecretKey), nil
	})

	if err != nil {
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var expired int64

		if expired, err = strconv.ParseInt(claims["expire"].(string), 10, 64); err != nil {
			return
		}

		if userId, err = strconv.ParseInt(claims["sub"].(string), 10, 64); err != nil {
			return
		}

		if time.Now().Unix() > expired {
			err = errors.New("expired token")
			return
		}

		return userId, claims["action"].(Action), nil
	}

	err = errors.New("invalid token")
	return
}
