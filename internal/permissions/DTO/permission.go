package dto

type Create struct {
	UserID     int `validate:"required, number"`
	Permission int `validate:"required,number ,oneof=1 2 4 3 5 6 7"`
}
