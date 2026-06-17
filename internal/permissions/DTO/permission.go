package dto

type Upsert struct {
	UserID     int `json:"userID" validate:"required,number"`
	Permission int `json:"permission" validate:"required,number,oneof=1 2 4 3 5 6 7"`
}

type Delete struct {
	UserID int `json:"userID" validate:"required, number"`
}
