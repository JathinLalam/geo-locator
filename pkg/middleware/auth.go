package middleware

import (
	"geo-locator/internal/auth"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	cognitoClient *auth.CognitoClient
}

func NewAuthMiddleware(cognitoClient *auth.CognitoClient) *AuthMiddleware {
	return &AuthMiddleware{
		cognitoClient: cognitoClient,
	}
}

func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		token := parts[1]
		userAttributes, err := m.cognitoClient.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", userAttributes.Email) // Using email as user ID for now
		c.Set("tenant_id", userAttributes.TenantID)
		c.Set("user_role", userAttributes.Role)
		c.Set("user_attributes", userAttributes)

		c.Next()
	}
}

func (m *AuthMiddleware) RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User role not found"})
			c.Abort()
			return
		}

		if userRole != requiredRole && userRole != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (m *AuthMiddleware) TenantContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := c.GetString("tenant_id")
		if tenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
			c.Abort()
			return
		}

		// Add tenant ID to all database queries
		c.Set("db_tenant_id", tenantID)
		c.Next()
	}
}
