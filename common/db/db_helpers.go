package db

import (
	"database/sql"
	"strconv"
	"strings"
)

func CreatePlaceholders(amountOfItems int) string {
	strLen := amountOfItems - 1
	for i := 1; i <= amountOfItems; i++ {
		s := strconv.Itoa(i)
		strLen += len(s)
	}

	var sb strings.Builder
	sb.Grow(strLen)

	for i := 1; i <= amountOfItems; i++ {
		s := strconv.Itoa(i)
		sb.WriteString("$")
		sb.WriteString(s)
		if i != amountOfItems {
			sb.WriteByte(',')
		}

	}

	return sb.String()
}

func CreateArgs[T any](items []T, capacity int) []any {
	args := make([]any, 0, capacity)
	for _, item := range items {
		args = append(args, item)
	}
	return args
}

func ReadRow[T any](rows *sql.Rows, storage *[]T) error {
	var item T
	err := rows.Scan(&item)
	if err != nil {
		return err
	}

	*storage = append(*storage, item)

	return nil
}
