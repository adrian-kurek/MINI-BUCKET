package dto

type JWTtoken struct {
	token string `validator:"jwt"`
}
