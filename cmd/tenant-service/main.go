package main

import (
	"fmt"
	"geo-locator/internal/auth"
	"geo-locator/internal/common/models"
	"geo-locator/pkg/config"
	"geo-locator/pkg/database"
	"geo-locator/pkg/middleware"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log"
	"net/http"
)

type TenantService struct {
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
		log.Printf("Warning: Cognito client initialization failed: %v", err)
		// Continue without Cognito for development
	}

	authMiddleware := middleware.NewAuthMiddleware(cognitoClient)
	tenantService := &TenantService{
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
	router.Use(tenantService.corsMiddleware())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "tenant-service",
		})
	})

	// Protected endpoints
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware.Authenticate())
	{
		// Tenant management (admin only)
		tenants := protected.Group("/tenants")
		tenants.Use(authMiddleware.RequireRole("admin"))
		{
			tenants.GET("", tenantService.getTenantsHandler)
			tenants.POST("", tenantService.createTenantHandler)
			tenants.GET("/:id", tenantService.getTenantHandler)
			tenants.PUT("/:id", tenantService.updateTenantHandler)
			tenants.DELETE("/:id", tenantService.deleteTenantHandler)
			tenants.GET("/:id/stats", tenantService.getTenantStatsHandler)
		}

		// Tenant user management
		tenantUsers := protected.Group("/tenant-users")
		tenantUsers.Use(tenantService.tenantContextMiddleware())
		{
			tenantUsers.GET("", tenantService.getTenantUsersHandler)
			tenantUsers.POST("", tenantService.addUserToTenantHandler)
			tenantUsers.PUT("/:userId", tenantService.updateUserRoleHandler)
			tenantUsers.DELETE("/:userId", tenantService.removeUserFromTenantHandler)
		}

		// Tenant configuration
		configs := protected.Group("/tenant-config")
		configs.Use(authMiddleware.RequireRole("admin"), tenantService.tenantContextMiddleware())
		{
			configs.GET("", tenantService.getTenantConfigHandler)
			configs.PUT("", tenantService.updateTenantConfigHandler)
		}
	}

	log.Printf("Tenant service starting on port %s", cfg.ServerPort)
	log.Fatal(router.Run(":" + cfg.ServerPort))
}

// Handler implementations
func (s *TenantService) getTenantsHandler(c *gin.Context) {
	var tenants []models.Tenant

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)
	offset := (page - 1) * pageSize

	if err := s.db.Offset(offset).Limit(pageSize).Find(&tenants).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": tenants,
		"page":    page,
		"size":    pageSize,
	})
}

func (s *TenantService) createTenantHandler(c *gin.Context) {
	var req struct {
		Name   string       `json:"name" binding:"required"`
		Domain string       `json:"domain" binding:"required"`
		Config models.JSONB `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if domain already exists
	var existingTenant models.Tenant
	if err := s.db.Where("domain = ?", req.Domain).First(&existingTenant).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Domain already exists"})
		return
	}

	tenant := models.Tenant{
		Name:   req.Name,
		Domain: req.Domain,
		Config: req.Config,
	}

	if err := s.db.Create(&tenant).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	// Create default configuration
	config := models.TenantConfiguration{
		TenantID: tenant.ID,
		Features: models.JSONB{"basic_tracking": true},
	}

	if err := s.db.Create(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant configuration"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Tenant created successfully",
		"tenant":  tenant,
	})
}

func (s *TenantService) getTenantHandler(c *gin.Context) {
	tenantID := c.Param("id")

	var tenant models.Tenant
	if err := s.db.Preload("Configurations").First(&tenant, "id = ?", tenantID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenant": tenant})
}

func (s *TenantService) updateTenantHandler(c *gin.Context) {
	tenantID := c.Param("id")

	var req struct {
		Name   string       `json:"name"`
		Domain string       `json:"domain"`
		Config models.JSONB `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var tenant models.Tenant
	if err := s.db.First(&tenant, "id = ?", tenantID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Domain != "" {
		// Check if new domain is unique
		var existing models.Tenant
		if err := s.db.Where("domain = ? AND id != ?", req.Domain, tenantID).First(&existing).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Domain already exists"})
			return
		}
		tenant.Domain = req.Domain
	}
	if req.Config != nil {
		tenant.Config = req.Config
	}

	if err := s.db.Save(&tenant).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tenant updated successfully",
		"tenant":  tenant,
	})
}

func (s *TenantService) deleteTenantHandler(c *gin.Context) {
	tenantID := c.Param("id")

	// Use transaction to ensure all related data is deleted
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Delete tenant (cascade will handle related records)
		if err := tx.Delete(&models.Tenant{}, "id = ?", tenantID).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted successfully"})
}

func (s *TenantService) getTenantStatsHandler(c *gin.Context) {
	tenantID := c.Param("id")

	stats := gin.H{
		"tenant_id": tenantID,
	}

	// Get user count
	var userCount int64
	s.db.Model(&models.User{}).Where("tenant_id = ?", tenantID).Count(&userCount)
	stats["user_count"] = userCount

	// Get active sessions count
	var activeSessions int64
	s.db.Model(&models.SessionMetadata{}).Where("tenant_id = ? AND status = 'active'", tenantID).Count(&activeSessions)
	stats["active_sessions"] = activeSessions

	// Get total location points
	var totalPoints int64
	s.db.Model(&models.LocationData{}).Where("tenant_id = ?", tenantID).Count(&totalPoints)
	stats["total_location_points"] = totalPoints

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func (s *TenantService) getTenantUsersHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var users []models.User
	if err := s.db.Where("tenant_id = ?", tenantID).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (s *TenantService) addUserToTenantHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var req struct {
		Email string `json:"email" binding:"required,email"`
		Role  string `json:"role" binding:"required,oneof=user admin"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists in tenant
	var existingUser models.User
	if err := s.db.Where("tenant_id = ? AND email = ?", tenantID, req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists in tenant"})
		return
	}

	// In a real scenario, you would invite the user via Cognito
	// For now, we'll create a placeholder user
	user := models.User{
		TenantID:      tenantID,
		CognitoUserID: "cognito-placeholder-" + req.Email, // This would come from Cognito
		Email:         req.Email,
		Role:          req.Role,
	}

	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to tenant"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User added to tenant successfully",
		"user":    user,
	})
}

func (s *TenantService) updateUserRoleHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.Param("userId")

	var req struct {
		Role string `json:"role" binding:"required,oneof=user admin"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := s.db.Where("id = ? AND tenant_id = ?", userID, tenantID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found in tenant"})
		return
	}

	user.Role = req.Role
	if err := s.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User role updated successfully",
		"user":    user,
	})
}

func (s *TenantService) removeUserFromTenantHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.Param("userId")

	if err := s.db.Where("id = ? AND tenant_id = ?", userID, tenantID).Delete(&models.User{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from tenant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User removed from tenant successfully"})
}

func (s *TenantService) getTenantConfigHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var config models.TenantConfiguration
	if err := s.db.Where("tenant_id = ?", tenantID).First(&config).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant configuration not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"config": config})
}

func (s *TenantService) updateTenantConfigHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var req struct {
		MaxUsers               *int         `json:"max_users"`
		MaxSessionsPerUser     *int         `json:"max_sessions_per_user"`
		LocationUpdateInterval *int         `json:"location_update_interval"`
		DataRetentionDays      *int         `json:"data_retention_days"`
		Features               models.JSONB `json:"features"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var config models.TenantConfiguration
	if err := s.db.Where("tenant_id = ?", tenantID).First(&config).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant configuration not found"})
		return
	}

	// Update fields if provided
	if req.MaxUsers != nil {
		config.MaxUsers = *req.MaxUsers
	}
	if req.MaxSessionsPerUser != nil {
		config.MaxSessionsPerUser = *req.MaxSessionsPerUser
	}
	if req.LocationUpdateInterval != nil {
		config.LocationUpdateInterval = *req.LocationUpdateInterval
	}
	if req.DataRetentionDays != nil {
		config.DataRetentionDays = *req.DataRetentionDays
	}
	if req.Features != nil {
		config.Features = req.Features
	}

	if err := s.db.Save(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tenant configuration updated successfully",
		"config":  config,
	})
}

// Middleware to enforce tenant context
func (s *TenantService) tenantContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userTenantID := c.GetString("tenant_id")
		if userTenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
			c.Abort()
			return
		}

		// For routes with tenant ID in path, verify the user has access
		if tenantID := c.Param("tenantId"); tenantID != "" && tenantID != userTenantID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access to this tenant is forbidden"})
			c.Abort()
			return
		}

		c.Set("db_tenant_id", userTenantID)
		c.Next()
	}
}

// Helper functions
func getPaginationParams(c *gin.Context) (page int, pageSize int) {
	page = 1
	pageSize = 20

	if p := c.Query("page"); p != "" {
		if parsed, err := parseInt(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if ps := c.Query("size"); ps != "" {
		if parsed, err := parseInt(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	return page, pageSize
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func (s *TenantService) corsMiddleware() gin.HandlerFunc {
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
