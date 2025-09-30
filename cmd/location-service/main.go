package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"geo-locator/internal/auth"
	"geo-locator/internal/common/models"
	"geo-locator/pkg/config"
	"geo-locator/pkg/database"
	"geo-locator/pkg/middleware"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type LocationService struct {
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
	}

	authMiddleware := middleware.NewAuthMiddleware(cognitoClient)
	locationService := &LocationService{
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
	router.Use(locationService.corsMiddleware())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "location-service",
		})
	})

	// Protected endpoints
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware.Authenticate())
	protected.Use(locationService.tenantContextMiddleware())
	{
		// Session management
		sessions := protected.Group("/sessions")
		{
			sessions.POST("", locationService.startSessionHandler)
			sessions.GET("", locationService.getSessionsHandler)
			sessions.GET("/:sessionId", locationService.getSessionHandler)
			sessions.DELETE("/:sessionId", locationService.endSessionHandler)
		}

		// Location data submission
		locations := protected.Group("/locations")
		locations.Use(locationService.rateLimitMiddleware())
		{
			locations.POST("/:sessionId", locationService.submitLocationHandler)
			locations.GET("/:sessionId/points", locationService.getLocationPointsHandler)
		}

		// Real-time session status
		protected.GET("/session-status/:sessionId", locationService.getSessionStatusHandler)
	}

	log.Printf("Location service starting on port %s", cfg.ServerPort)
	log.Fatal(router.Run(":" + cfg.ServerPort))
}

// Request/Response structures
type StartSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

type SubmitLocationRequest struct {
	Latitude  float64 `json:"latitude" binding:"required,min=-90,max=90"`
	Longitude float64 `json:"longitude" binding:"required,min=-180,max=180"`
	Accuracy  float64 `json:"accuracy"`
	Timestamp string  `json:"timestamp"` // Optional, defaults to current time
}

type SessionResponse struct {
	SessionID   string     `json:"session_id"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	TotalPoints int        `json:"total_points"`
	UserID      string     `json:"user_id"`
}

// Handlers
func (s *LocationService) startSessionHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")

	var req StartSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check tenant configuration for session limits
	var config models.TenantConfiguration
	if err := s.db.Where("tenant_id = ?", tenantID).First(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant configuration not found"})
		return
	}

	// Check if user has reached session limit
	var activeSessions int64
	s.db.Model(&models.SessionMetadata{}).
		Where("tenant_id = ? AND user_id = ? AND status = 'active'", tenantID, userID).
		Count(&activeSessions)

	if int(activeSessions) >= config.MaxSessionsPerUser {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":        "Maximum active sessions reached",
			"max_sessions": config.MaxSessionsPerUser,
		})
		return
	}

	// Check if session already exists
	var existingSession models.SessionMetadata
	if err := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, req.SessionID).First(&existingSession).Error; err == nil {
		if existingSession.Status == "active" {
			c.JSON(http.StatusConflict, gin.H{"error": "Session already active"})
			return
		}
		// Reactivate ended session
		existingSession.Status = "active"
		existingSession.EndedAt = nil
		existingSession.TotalPoints = 0
		if err := s.db.Save(&existingSession).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reactivate session"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Session reactivated",
			"session": s.sessionToResponse(&existingSession),
		})
		return
	}

	// Create new session
	session := models.SessionMetadata{
		TenantID:  tenantID,
		UserID:    userID,
		SessionID: req.SessionID,
		Status:    "active",
		StartedAt: time.Now(),
	}

	if err := s.db.Create(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Create audit log
	s.createAuditLog(tenantID, userID, "session_started", "session", req.SessionID, gin.H{
		"session_id": req.SessionID,
		"user_id":    userID,
	}, c)

	s.notifySessionEvent(tenantID, session.ID, userID, "session_started", gin.H{
		"session_id": req.SessionID,
		"user_id":    userID,
	})

	c.JSON(http.StatusCreated, gin.H{
		"message": "Session started successfully",
		"session": s.sessionToResponse(&session),
	})
}

func (s *LocationService) getSessionsHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)
	offset := (page - 1) * pageSize

	var sessions []models.SessionMetadata
	query := s.db.Where("tenant_id = ?", tenantID)

	// Non-admin users can only see their own sessions
	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&sessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
		return
	}

	// Convert to response format
	var response []SessionResponse
	for _, session := range sessions {
		response = append(response, s.sessionToResponse(&session))
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": response,
		"page":     page,
		"size":     pageSize,
	})
}

func (s *LocationService) getSessionHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	var session models.SessionMetadata
	query := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID)

	// Non-admin users can only see their own sessions
	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"session": s.sessionToResponse(&session)})
}

func (s *LocationService) endSessionHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	var session models.SessionMetadata
	query := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID)

	// Non-admin users can only end their own sessions
	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch session"})
		return
	}

	if session.Status == "completed" {
		c.JSON(http.StatusConflict, gin.H{"error": "Session already completed"})
		return
	}

	now := time.Now()
	session.Status = "completed"
	session.EndedAt = &now

	if err := s.db.Save(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to end session"})
		return
	}

	// Create audit log
	s.createAuditLog(tenantID, userID, "session_ended", "session", sessionID, gin.H{
		"session_id":       sessionID,
		"total_points":     session.TotalPoints,
		"duration_minutes": time.Since(session.StartedAt).Minutes(),
	}, c)

	s.notifySessionEvent(tenantID, sessionID, userID, "session_ended", gin.H{
		"session_id":    sessionID,
		"total_points":  session.TotalPoints,
		"duration_mins": time.Since(session.StartedAt).Minutes(),
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "Session ended successfully",
		"session": s.sessionToResponse(&session),
	})
}

func (s *LocationService) submitLocationHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	var req SubmitLocationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate location data
	if err := s.validateLocationData(req.Latitude, req.Longitude, req.Accuracy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if session exists and is active
	var session models.SessionMetadata
	if err := s.db.Where("tenant_id = ? AND session_id = ? AND user_id = ?", tenantID, sessionID, userID).
		First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session"})
		return
	}

	if session.Status != "active" {
		c.JSON(http.StatusConflict, gin.H{"error": "Session is not active"})
		return
	}

	// Parse timestamp or use current time
	var timestamp time.Time
	if req.Timestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid timestamp format, use RFC3339"})
			return
		}
		timestamp = parsedTime
	} else {
		timestamp = time.Now()
	}

	// Create location data record
	location := models.LocationData{
		TenantID:  tenantID,
		UserID:    userID,
		SessionID: sessionID,
		Latitude:  req.Latitude,
		Longitude: req.Longitude,
		Accuracy:  req.Accuracy,
		Timestamp: timestamp,
	}

	// Use transaction to ensure both operations succeed
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Save location data
		if err := tx.Create(&location).Error; err != nil {
			return err
		}

		// Update session point count
		if err := tx.Model(&models.SessionMetadata{}).
			Where("tenant_id = ? AND session_id = ?", tenantID, sessionID).
			Update("total_points", gorm.Expr("total_points + ?", 1)).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save location data"})
		return
	}

	s.notifyStreamingService(tenantID, sessionID, userID, &location)

	c.JSON(http.StatusCreated, gin.H{
		"message": "Location data submitted successfully",
		"location": gin.H{
			"id":        location.ID,
			"latitude":  location.Latitude,
			"longitude": location.Longitude,
			"accuracy":  location.Accuracy,
			"timestamp": location.Timestamp,
		},
	})
}

func (s *LocationService) getLocationPointsHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	// Check if user has access to this session
	var session models.SessionMetadata
	query := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID)

	// Non-admin users can only see their own sessions
	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch session"})
		return
	}

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)
	offset := (page - 1) * pageSize

	var locations []models.LocationData
	if err := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID).
		Order("timestamp ASC").
		Offset(offset).
		Limit(pageSize).
		Find(&locations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch location data"})
		return
	}

	// Convert to response format
	var response []gin.H
	for _, loc := range locations {
		response = append(response, gin.H{
			"id":        loc.ID,
			"latitude":  loc.Latitude,
			"longitude": loc.Longitude,
			"accuracy":  loc.Accuracy,
			"timestamp": loc.Timestamp,
			"user_id":   loc.UserID,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"locations": response,
		"page":      page,
		"size":      pageSize,
		"total":     session.TotalPoints,
	})
}

func (s *LocationService) getSessionStatusHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	var session models.SessionMetadata
	query := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID)

	// Non-admin users can only see their own sessions
	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch session"})
		return
	}

	// Get recent location points (last 10)
	var recentLocations []models.LocationData
	s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID).
		Order("timestamp DESC").
		Limit(10).
		Find(&recentLocations)

	response := gin.H{
		"session":          s.sessionToResponse(&session),
		"recent_locations": recentLocations,
		"is_active":        session.Status == "active",
	}

	c.JSON(http.StatusOK, response)
}

// Helper methods
func (s *LocationService) validateLocationData(lat, lng, accuracy float64) error {
	if lat < -90 || lat > 90 {
		return fmt.Errorf("latitude must be between -90 and 90")
	}
	if lng < -180 || lng > 180 {
		return fmt.Errorf("longitude must be between -180 and 180")
	}
	if accuracy < 0 {
		return fmt.Errorf("accuracy must be non-negative")
	}
	return nil
}

func (s *LocationService) sessionToResponse(session *models.SessionMetadata) SessionResponse {
	return SessionResponse{
		SessionID:   session.SessionID,
		Status:      session.Status,
		StartedAt:   session.StartedAt,
		EndedAt:     session.EndedAt,
		TotalPoints: session.TotalPoints,
		UserID:      session.UserID,
	}
}

func (s *LocationService) createAuditLog(tenantID, userID, action, resourceType, resourceID string, details gin.H, c *gin.Context) {
	auditLog := models.AuditLog{
		TenantID:     tenantID,
		UserID:       &userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   &resourceID,
		Details:      models.JSONB(details),
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	}

	// Log in background (don't block the request)
	go func() {
		if err := s.db.Create(&auditLog).Error; err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
	}()
}

// Rate limiting middleware
func (s *LocationService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := c.GetString("tenant_id")
		userID := c.GetString("user_id")
		endpoint := c.FullPath()

		// Get tenant configuration
		var config models.TenantConfiguration
		if err := s.db.Where("tenant_id = ?", tenantID).First(&config).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant configuration not found"})
			c.Abort()
			return
		}

		// Check rate limits (simplified implementation)
		// In production, you might use Redis for distributed rate limiting
		windowStart := time.Now().Truncate(time.Minute)
		windowEnd := windowStart.Add(time.Minute)

		var rateLimit models.RateLimit
		err := s.db.Where("tenant_id = ? AND user_id = ? AND endpoint = ? AND window_start = ?",
			tenantID, userID, endpoint, windowStart).
			First(&rateLimit).Error

		if err == gorm.ErrRecordNotFound {
			// Create new rate limit record
			rateLimit = models.RateLimit{
				TenantID:     tenantID,
				UserID:       &userID,
				Endpoint:     endpoint,
				RequestCount: 1,
				WindowStart:  windowStart,
				WindowEnd:    windowEnd,
			}
			if err := s.db.Create(&rateLimit).Error; err != nil {
				log.Printf("Failed to create rate limit record: %v", err)
			}
		} else if err == nil {
			// Update existing rate limit
			maxRequests := 60 // Default: 1 request per second
			if config.LocationUpdateInterval > 0 {
				maxRequests = 60 / config.LocationUpdateInterval
			}

			if rateLimit.RequestCount >= maxRequests {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error":       "Rate limit exceeded",
					"retry_after": windowEnd.Sub(time.Now()).Seconds(),
				})
				c.Abort()
				return
			}

			rateLimit.RequestCount++
			if err := s.db.Save(&rateLimit).Error; err != nil {
				log.Printf("Failed to update rate limit record: %v", err)
			}
		}

		c.Next()
	}
}

// Tenant context middleware
func (s *LocationService) tenantContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userTenantID := c.GetString("tenant_id")
		if userTenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
			c.Abort()
			return
		}

		c.Set("db_tenant_id", userTenantID)
		c.Next()
	}
}

// CORS middleware
func (s *LocationService) corsMiddleware() gin.HandlerFunc {
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

// Helper functions (same as tenant service)
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

func (s *LocationService) notifyStreamingService(tenantID, sessionID, userID string, location *models.LocationData) {
	// Prepare the payload
	payload := gin.H{
		"tenant_id":  tenantID,
		"session_id": sessionID,
		"user_id":    userID,
		"latitude":   location.Latitude,
		"longitude":  location.Longitude,
		"accuracy":   location.Accuracy,
		"timestamp":  location.Timestamp.Format(time.RFC3339),
	}

	// Send to streaming service (non-blocking)
	go func() {
		streamingServiceURL := "http://localhost:8083/internal/location-update" // Adjust port as needed

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Printf("Failed to marshal location update: %v", err)
			return
		}

		req, err := http.NewRequest("POST", streamingServiceURL, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to create request to streaming service: %v", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Internal-Service-Token")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send location update to streaming service: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Streaming service returned error: %d", resp.StatusCode)
		}
	}()
}

// Notify streaming service about session event
func (s *LocationService) notifySessionEvent(tenantID, sessionID, userID, eventType string, data gin.H) {
	payload := gin.H{
		"tenant_id":  tenantID,
		"session_id": sessionID,
		"user_id":    userID,
		"event_type": eventType,
		"data":       data,
	}

	go func() {
		streamingServiceURL := "http://localhost:8083/internal/session-event"

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Printf("Failed to marshal session event: %v", err)
			return
		}

		req, err := http.NewRequest("POST", streamingServiceURL, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to create request to streaming service: %v", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Internal-Service-Token")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send session event to streaming service: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Streaming service returned error for session event: %d", resp.StatusCode)
		}
	}()
}
