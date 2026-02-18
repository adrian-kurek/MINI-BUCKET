package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

// type userClaims struct {
// 	ID       int    `json:"id" example:"11"`
// 	Email    string `json:"email" example:"joedoe@email.com"`
// 	UserName string `json:"username" example:"slodkiadrianek"`
// 	exp      int64
// 	jwt.RegisteredClaims
// }

type Authorization struct {
	accessTokenSecret  string
	refreshTokenSecret string
	loggerService      commonInterfaces.Logger
}

func NewAuthorization(accessTokenSecret string, refreshTokenSecret string, loggerService commonInterfaces.Logger) *Authorization {
	return &Authorization{
		accessTokenSecret:  accessTokenSecret,
		refreshTokenSecret: refreshTokenSecret,
		loggerService:      loggerService,
	}
}

func (ar Authorization) GenerataRefreshToken() ([]byte, error) {
	bytes := make([]byte, 64)

	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (ar Authorization) HashToken(token []byte) string {
	hasher := sha256.New()
	hasher.Write(token)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (ar Authorization) GenerateAccessToken(user userModel.User) (string, error) {
	ar.loggerService.Info("started signing a new access token", nil)
	tokenWithData := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.ID,
		"email":    user.Email,
		"username": user.Username,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
	})

	tokenString, err := tokenWithData.SignedString([]byte(ar.accessTokenSecret))
	if err != nil {
		errMsg := errors.New("failed to sign access token properly")
		ar.loggerService.Error(errMsg.Error(), err)
		return "", commonErrors.NewAPIError(http.StatusUnauthorized, errMsg.Error())
	}

	ar.loggerService.Info("Successfully signed a new access token", nil)
	return tokenString, nil
}

// func (j Authorization) parseClaimsFromToken(tokenString string) (*jwt.Token, userClaims, error) {
// 	var user userClaims
// 	token, err := jwt.ParseWithClaims(tokenString, &user, func(token *jwt.Token) (any, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return []byte(j.token), nil
// 	})
// 	if err != nil {
// 		return nil, userClaims{}, err
// 	}
// 	return token, user, nil
// }
//
// func (j Authorization) VerifyToken(r *http.Request) error {
// 	authHeader := r.Header.Get("Authorization")
// 	if !strings.HasPrefix(authHeader, "Bearer ") {
// 		j.loggerService.Info("token is missing", authHeader)
// 		err := models.NewError(401, "Authorization", "Failed to authorize a user")
// 		response.SetError(w, r, err)
// 		return
// 	}
//
// 	tokenString := strings.Split(authHeader, " ")[1]
//
// 	tokenWithData, user, err := j.parseClaimsFromToken(tokenString)
// 	if err != nil {
// 		j.loggerService.Info("Failed to read data properly", err.Error())
// 		err := models.NewError(401, "Authorization", "Provided token is invalid")
// 		response.SetError(w, r, err)
// 		return
//
// 	}
//
// 	if !tokenWithData.Valid {
// 		err := errors.New("provided token is invalid")
// 		j.loggerService.Info(err.Error(), tokenString)
// 		return commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
// 	}
//
// 	r = utils.SetContext(r, "id", user.ID)
//
// 	r = utils.SetContext(r, "email", user.Email)
// 	return nil
// }
//
// func (j Authorization) BlacklistUser(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		authHeader := r.Header.Get("Authorization")
// 		if !strings.HasPrefix(authHeader, "Bearer ") {
// 			j.loggerService.Info("token is missing", authHeader)
// 			err := models.NewError(401, "Authorization", "Failed to authorize a user")
// 			response.SetError(w, r, err)
// 			return
// 		}
//
// 		tokenString := strings.Split(authHeader, " ")[1]
//
// 		tokenWithData, user, err := j.parseClaimsFromToken(tokenString)
// 		if err != nil {
// 			j.loggerService.Info("Failed to read data properly", tokenString)
// 			err := models.NewError(401, "Authorization", "Failed to read token")
// 			response.SetError(w, r, err)
// 			return
// 		}
//
// 		if !tokenWithData.Valid {
// 			j.loggerService.Info("Provided token is invalid", tokenString)
// 			err := models.NewError(401, "Authorization", "Provided token is invalid")
// 			response.SetError(w, r, err)
// 			return
// 		}
//
// 		expirationTime := time.Until(user.ExpiresAt.Time)
//
// 		next.ServeHTTP(w, r)
// 	})
// }
