package dto

type CreateUser struct {
	Username        string `json:"username" validate:"required,min=6"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=12"`
	ConfirmPassword string `json:"confirmPassword" validate:"required,eqfield=Password"`
}

type LoginUser struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
