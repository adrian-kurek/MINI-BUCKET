package repository

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)
func (or *ObjectRepository) DeleteOne(ctx context.Context, objectKey string) error {
	query := "DELETE FROM objects WHERE object_key = $1"
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	_, err = stmt.ExecContext(ctx, objectKey)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) createPlaceholders(amountOfItems int) string {
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


func (or *ObjectRepository) DeleteMany(ctx context.Context, objectKeys []string) error {
	placeholders := or.createPlaceholders(len(objectKeys))
	query := fmt.Sprintf("DELETE FROM objects WHERE object_key ( %s )", placeholders)

	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_keys": objectKeys,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, objectKeys)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_keys": objectKeys,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
