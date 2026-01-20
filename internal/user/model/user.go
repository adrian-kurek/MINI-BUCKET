package model

import "time"

type User struct {
	ID            int
	Email         string
	Username      string
	Password      string
	EmailVerified bool
	CreatedAt     time.Time
}
