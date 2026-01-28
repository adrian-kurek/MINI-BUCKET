package dto

type CreateUser struct {
	Username        string `validate:"required,min=6"`
	Email           string `validate:"required,email"`
	Password        string `validate:"required,min=12,strong_password"`
	ConfirmPassword string `validate:"required,eqfield=Password"`
}
