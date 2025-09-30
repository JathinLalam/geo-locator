package main

import (
	"geo-locator/internal/auth"
	"geo-locator/internal/common/models"
	"geo-locator/pkg/config"
	"geo-locator/pkg/database"
	"geo-locator/pkg/middleware"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthService struct {
	db             *database.DB
	cognitoClient  *auth.CognitoClient
	authMiddleware *middleware.AuthMiddleware
}

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.NewDB(cfg)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	// Initialize Cognito client
	cognitoClient, err := auth.NewCognitoClient(cfg)
	if err != nil {
		log.Fatal("Failed to initialize Cognito client:", err)
	}

	authMiddleware := middleware.NewAuthMiddleware(cognitoClient)
	authService := &AuthService{
		db:             db,
		cognitoClient:  cognitoClient,
		authMiddleware: authMiddleware,
	}

	// Set up Gin router
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Middleware
	router.Use(authService.corsMiddleware())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	// Public endpoints
	router.POST("/auth/login", authService.loginHandler)
	router.POST("/auth/register", authService.registerHandler)

	// Protected endpoints
	protected := router.Group("/auth")
	protected.Use(authMiddleware.Authenticate())
	{
		protected.POST("/refresh", authService.refreshTokenHandler)
		protected.POST("/validate", authService.validateTokenHandler)
		protected.GET("/profile", authService.getProfileHandler)
	}

	// Admin endpoints
	admin := protected.Group("/admin")
	admin.Use(authMiddleware.RequireRole("admin"))
	{
		admin.POST("/tenants", authService.createTenantHandler)
		admin.GET("/tenants", authService.getTenantsHandler)
	}

	log.Printf("Auth service starting on port %s", cfg.ServerPort)
	log.Fatal(router.Run(":" + cfg.ServerPort))
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	TenantID string `json:"tenant_id" binding:"required,uuid"`
	Role     string `json:"role" binding:"required,oneof=user admin"`
}

func (s *AuthService) loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authResult, err := s.cognitoClient.SignIn(req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  authResult.AccessToken,
		"id_token":      authResult.IDToken,
		"refresh_token": authResult.RefreshToken,
		"expires_in":    authResult.ExpiresIn,
	})
}

func (s *AuthService) registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if tenant exists
	var tenant models.Tenant
	if err := s.db.Where("id = ?", req.TenantID).First(&tenant).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant not found"})
		return
	}

	// Register user in Cognito
	userSub, err := s.cognitoClient.SignUp(req.Email, req.Password, req.TenantID, req.Role)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Registration failed", "details": err.Error()})
		return
	}

	// Create user in database
	user := models.User{
		TenantID:      req.TenantID,
		CognitoUserID: userSub,
		Email:         req.Email,
		Role:          req.Role,
	}

	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user record"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user_id": user.ID,
	})
}

func (s *AuthService) refreshTokenHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authResult, err := s.cognitoClient.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token refresh failed", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": authResult.AccessToken,
		"id_token":     authResult.IDToken,
		"expires_in":   authResult.ExpiresIn,
	})
}

func (s *AuthService) validateTokenHandler(c *gin.Context) {
	// Token is already validated by middleware, just return user info
	userAttributes, exists := c.Get("user_attributes")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User attributes not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user":  userAttributes,
	})
}

func (s *AuthService) getProfileHandler(c *gin.Context) {
	userAttributes, exists := c.Get("user_attributes")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User attributes not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"profile": userAttributes,
	})
}

func (s *AuthService) createTenantHandler(c *gin.Context) {
	var req struct {
		Name   string `json:"name" binding:"required"`
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant := models.Tenant{
		Name:   req.Name,
		Domain: req.Domain,
		Config: models.JSONB{"max_users": 100, "features": []string{"basic_tracking"}},
	}

	if err := s.db.Create(&tenant).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Tenant created successfully",
		"tenant":  tenant,
	})
}

func (s *AuthService) getTenantsHandler(c *gin.Context) {
	var tenants []models.Tenant
	if err := s.db.Find(&tenants).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": tenants,
	})
}

func (s *AuthService) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
