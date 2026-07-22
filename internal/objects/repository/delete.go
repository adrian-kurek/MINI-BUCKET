package repository

import (
	"context"
	"fmt"

	"github.com/slodkiadrianek/MINI-BUCKET/common/db"
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



func (or *ObjectRepository) DeleteMany(ctx context.Context, objectKeys []string) error {
	placeholders := db.CreatePlaceholders(len(objectKeys))
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
