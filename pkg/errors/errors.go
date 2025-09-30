package errors

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	Err     error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func NewAppError(code int, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Common errors
var (
	ErrUnauthorized       = NewAppError(http.StatusUnauthorized, "Unauthorized", nil)
	ErrForbidden          = NewAppError(http.StatusForbidden, "Forbidden", nil)
	ErrNotFound           = NewAppError(http.StatusNotFound, "Resource not found", nil)
	ErrValidation         = NewAppError(http.StatusBadRequest, "Validation failed", nil)
	ErrRateLimit          = NewAppError(http.StatusTooManyRequests, "Rate limit exceeded", nil)
	ErrInternal           = NewAppError(http.StatusInternalServerError, "Internal server error", nil)
	ErrServiceUnavailable = NewAppError(http.StatusServiceUnavailable, "Service unavailable", nil)
)

// Error handler middleware
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err

			var appErr *AppError
			switch e := err.(type) {
			case *AppError:
				appErr = e
			default:
				appErr = ErrInternal
				appErr.Details = err.Error()
			}

			// Log error
			logError(c, appErr)

			c.JSON(appErr.Code, gin.H{
				"error":   appErr.Message,
				"details": appErr.Details,
				"code":    appErr.Code,
			})
		}
	}
}

func logError(c *gin.Context, err *AppError) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")

	log.Printf("[ERROR] %s %s %d tenant=%s user=%s error=%v",
		c.Request.Method,
		c.Request.URL.Path,
		err.Code,
		tenantID,
		userID,
		err,
	)
}
