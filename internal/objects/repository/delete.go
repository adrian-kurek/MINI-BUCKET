package repository

import 
(
	"context"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)

func (or *ObjectRepository) Delete(ctx context.Context, objectKey string) error {
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
