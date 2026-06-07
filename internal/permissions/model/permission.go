package model

import "time"

type Permission struct {
	ID         int
	bucketID   int
	userID     int
	permission int
	updatedAt  time.Time
	createdAt  time.Time
}
