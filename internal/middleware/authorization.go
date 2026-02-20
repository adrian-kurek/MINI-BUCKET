package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type Authorization struct {
	accessTokenSecret  string
	refreshTokenSecret string
	loggerService      commonInterfaces.Logger
	cacheService       commonInterfaces.CacheService
}

func NewAuthorization(accessTokenSecret string, refreshTokenSecret string, loggerService commonInterfaces.Logger, cacheService commonInterfaces.CacheService) *Authorization {
	return &Authorization{
		accessTokenSecret:  accessTokenSecret,
		refreshTokenSecret: refreshTokenSecret,
		loggerService:      loggerService,
		cacheService:       cacheService,
	}
}

func (ar Authorization) GenerateRefreshToken() ([]byte, error) {
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

func (ar Authorization) parseClaimsFromToken(tokenString string) (*jwt.Token, userModel.UserClaims, error) {
	var user userModel.UserClaims
	token, err := jwt.ParseWithClaims(tokenString, &user, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ar.accessTokenSecret), nil
	})
	if err != nil {
		return nil, userModel.UserClaims{}, err
	}
	return token, user, nil
}

func (ar Authorization) VerifyToken(r *http.Request) (*http.Request, error) {
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		return r, err
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ar.loggerService.Info("token is missing", authHeader)
		return r, commonErrors.NewAPIError(http.StatusUnauthorized, "failed to authorize a user")
	}

	tokenString := strings.Split(authHeader, " ")[1]

	if err := ctx.Err(); err != nil {
		return r, err
	}

	tokenWithData, user, err := ar.parseClaimsFromToken(tokenString)
	if err != nil {
		ar.loggerService.Info("failed to read data properly", err.Error())
		return r, commonErrors.NewAPIError(401, "provided token is invalid")
	}

	if err := ctx.Err(); err != nil {
		return r, err
	}

	if !tokenWithData.Valid {
		err := errors.New("provided token is invalid")
		ar.loggerService.Info(err.Error(), tokenString)
		return r, commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	r = request.SetContext(r, "id", user.ID)
	r = request.SetContext(r, "email", user.Email)
	r = request.SetContext(r, "username", user.Username)
	return r, nil
}

func (ar Authorization) BlacklistUser(ctx context.Context, r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ar.loggerService.Info("token is missing", authHeader)
		return commonErrors.NewAPIError(http.StatusUnauthorized, "failed to authorize a user")
	}

	tokenString := strings.Split(authHeader, " ")[1]

	tokenWithData, user, err := ar.parseClaimsFromToken(tokenString)
	if err != nil {
		ar.loggerService.Info("failed to read data properly", tokenString)
		return commonErrors.NewAPIError(http.StatusUnauthorized, "failed to read token")
	}

	if !tokenWithData.Valid {
		ar.loggerService.Info("provided token is invalid", tokenString)
		return commonErrors.NewAPIError(http.StatusUnauthorized, "provided token is invalid")
	}

	cacheKey := "tokenBlackList-" + tokenString
	result, err := ar.cacheService.ExistsData(ctx, cacheKey)
	if err != nil {
		ar.loggerService.Info("failed to check blacklist", err)
		return err
	}

	if result > 0 {
		err := errors.New("token already blacklisted")
		ar.loggerService.Info(err.Error(), tokenString)
		return commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	expirationTime := time.Until(user.ExpiresAt.Time)

	err = ar.cacheService.SetData(ctx, cacheKey, "true", expirationTime)
	if err != nil {
		ar.loggerService.Info("failed to set data in cache", err)
		return err
	}

	return nil
}
