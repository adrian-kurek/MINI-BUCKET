package DTO

type JWTtoken struct {
	token string `validator:"jwt"`
}
