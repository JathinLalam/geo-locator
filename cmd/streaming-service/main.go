package main

import (
	"encoding/json"
	"geo-locator/internal/auth"
	"geo-locator/internal/common/models"
	"geo-locator/pkg/config"
	"geo-locator/pkg/database"
	"geo-locator/pkg/middleware"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
)

type StreamingService struct {
	db             *database.DB
	cognitoClient  *auth.CognitoClient
	authMiddleware *middleware.AuthMiddleware
	upgrader       websocket.Upgrader
	clients        *ClientManager
}

type ClientManager struct {
	clients    map[string]map[string]*Client // tenantID -> sessionID -> client
	broadcast  chan BroadcastMessage
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

type Client struct {
	tenantID  string
	sessionID string
	conn      *websocket.Conn
	send      chan []byte
}

type BroadcastMessage struct {
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
	Data      any    `json:"data"`
	Type      string `json:"type"` // location_update, session_start, session_end
}

type ThirdPartyConfig struct {
	Endpoint string `json:"endpoint"`
	APIKey   string `json:"api_key"`
	Protocol string `json:"protocol"` // websocket, http, kafka
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

	// Initialize WebSocket upgrader
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in development
		},
	}

	// Initialize client manager
	clientManager := &ClientManager{
		clients:    make(map[string]map[string]*Client),
		broadcast:  make(chan BroadcastMessage, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	streamingService := &StreamingService{
		db:             db,
		cognitoClient:  cognitoClient,
		authMiddleware: authMiddleware,
		upgrader:       upgrader,
		clients:        clientManager,
	}

	// Start client manager
	go clientManager.run()

	// Start location data processor
	go streamingService.processLocationData()

	// Set up Gin router
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Middleware
	router.Use(streamingService.corsMiddleware())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "streaming-service",
			"clients": len(clientManager.getAllClients()),
		})
	})

	// WebSocket endpoint for third-party applications
	router.GET("/ws/third-party", streamingService.thirdPartyWebSocketHandler)

	// WebSocket endpoint for tenant applications
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware.Authenticate())
	protected.Use(streamingService.tenantContextMiddleware())
	{
		protected.GET("/ws/session/:sessionId", streamingService.sessionWebSocketHandler)
		protected.POST("/streaming/config", streamingService.updateStreamingConfigHandler)
		protected.GET("/streaming/config", streamingService.getStreamingConfigHandler)
		protected.GET("/streaming/connections", streamingService.getActiveConnectionsHandler)
		protected.POST("/streaming/broadcast/:sessionId", streamingService.broadcastToSessionHandler)
	}

	// Internal API for location service to push updates
	internal := router.Group("/internal")
	internal.Use(streamingService.internalAuthMiddleware())
	{
		internal.POST("/location-update", streamingService.handleLocationUpdate)
		internal.POST("/session-event", streamingService.handleSessionEvent)
	}

	log.Printf("Streaming service starting on port %s", cfg.ServerPort)
	log.Fatal(router.Run(":" + cfg.ServerPort))
}

// Client Manager methods
func (cm *ClientManager) run() {
	for {
		select {
		case client := <-cm.register:
			cm.mu.Lock()
			if cm.clients[client.tenantID] == nil {
				cm.clients[client.tenantID] = make(map[string]*Client)
			}
			cm.clients[client.tenantID][client.sessionID] = client
			cm.mu.Unlock()
			log.Printf("Client registered: tenant=%s, session=%s", client.tenantID, client.sessionID)

		case client := <-cm.unregister:
			cm.mu.Lock()
			if tenants, ok := cm.clients[client.tenantID]; ok {
				if _, ok := tenants[client.sessionID]; ok {
					delete(tenants, client.sessionID)
					close(client.send)
					if len(tenants) == 0 {
						delete(cm.clients, client.tenantID)
					}
				}
			}
			cm.mu.Unlock()
			log.Printf("Client unregistered: tenant=%s, session=%s", client.tenantID, client.sessionID)

		case message := <-cm.broadcast:
			cm.mu.RLock()
			clients := cm.getClientsForBroadcast(message.TenantID, message.SessionID)
			cm.mu.RUnlock()

			data, err := json.Marshal(message)
			if err != nil {
				log.Printf("Error marshaling broadcast message: %v", err)
				continue
			}

			for _, client := range clients {
				select {
				case client.send <- data:
				default:
					close(client.send)
					cm.mu.Lock()
					delete(cm.clients[client.tenantID], client.sessionID)
					cm.mu.Unlock()
				}
			}
		}
	}
}

func (cm *ClientManager) getClientsForBroadcast(tenantID, sessionID string) []*Client {
	var clients []*Client

	if sessionID != "" {
		// Broadcast to specific session
		if tenantClients, ok := cm.clients[tenantID]; ok {
			if client, ok := tenantClients[sessionID]; ok {
				clients = append(clients, client)
			}
		}
	} else {
		// Broadcast to all sessions in tenant
		if tenantClients, ok := cm.clients[tenantID]; ok {
			for _, client := range tenantClients {
				clients = append(clients, client)
			}
		}
	}

	return clients
}

func (cm *ClientManager) getAllClients() []*Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var allClients []*Client
	for _, tenantClients := range cm.clients {
		for _, client := range tenantClients {
			allClients = append(allClients, client)
		}
	}
	return allClients
}

func (cm *ClientManager) getClientCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	count := 0
	for _, tenantClients := range cm.clients {
		count += len(tenantClients)
	}
	return count
}

// WebSocket handlers
func (s *StreamingService) thirdPartyWebSocketHandler(c *gin.Context) {
	// This endpoint is for third-party applications to connect
	// They should provide tenant ID and API key for authentication

	tenantID := c.Query("tenant_id")
	apiKey := c.Query("api_key")
	sessionID := c.Query("session_id")

	if tenantID == "" || apiKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id and api_key are required"})
		return
	}

	// Validate API key (in production, use proper API key validation)
	var config models.TenantConfiguration
	if err := s.db.Where("tenant_id = ?", tenantID).First(&config).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant or API key"})
		return
	}

	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		tenantID:  tenantID,
		sessionID: sessionID, // empty means all sessions for the tenant
		conn:      conn,
		send:      make(chan []byte, 256),
	}

	s.clients.register <- client

	// Start goroutines for this client
	go client.writePump()
	go client.readPump(s.clients)

	log.Printf("Third-party WebSocket connected: tenant=%s, session=%s", tenantID, sessionID)
}

func (s *StreamingService) sessionWebSocketHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")
	sessionID := c.Param("sessionId")

	// Verify user has access to this session
	var session models.SessionMetadata
	query := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, sessionID)

	if userRole := c.GetString("user_role"); userRole != "admin" {
		query = query.Where("user_id = ?", userID)
	}

	if err := query.First(&session).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to session"})
		return
	}

	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		tenantID:  tenantID,
		sessionID: sessionID,
		conn:      conn,
		send:      make(chan []byte, 256),
	}

	s.clients.register <- client

	// Start goroutines for this client
	go client.writePump()
	go client.readPump(s.clients)

	log.Printf("Session WebSocket connected: tenant=%s, session=%s, user=%s", tenantID, sessionID, userID)
}

// Client read/write pumps
func (c *Client) readPump(cm *ClientManager) {
	defer func() {
		cm.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512) // 512 bytes
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		// Handle incoming messages from clients
		log.Printf("Received message from client: %s", string(message))
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second) // Ping interval
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Channel closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current websocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// HTTP handlers
func (s *StreamingService) updateStreamingConfigHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var req struct {
		ThirdPartyEndpoint string `json:"third_party_endpoint"`
		APIKey             string `json:"api_key"`
		Protocol           string `json:"protocol"`
		Enabled            bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update or create streaming session configuration
	var streamingSession models.StreamingSession
	err := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, "default").
		First(&streamingSession).Error

	if err == gorm.ErrRecordNotFound {
		streamingSession = models.StreamingSession{
			TenantID:           tenantID,
			SessionID:          "default",
			ThirdPartyEndpoint: req.ThirdPartyEndpoint,
			Status:             "active",
		}
		if err := s.db.Create(&streamingSession).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create streaming config"})
			return
		}
	} else if err == nil {
		streamingSession.ThirdPartyEndpoint = req.ThirdPartyEndpoint
		if err := s.db.Save(&streamingSession).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update streaming config"})
			return
		}
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Streaming configuration updated successfully",
		"config":  streamingSession,
	})
}

func (s *StreamingService) getStreamingConfigHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var streamingSession models.StreamingSession
	if err := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, "default").
		First(&streamingSession).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Streaming configuration not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch streaming config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"config": streamingSession})
}

func (s *StreamingService) getActiveConnectionsHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	s.clients.mu.RLock()
	tenantClients := s.clients.clients[tenantID]
	connectionCount := len(tenantClients)

	var sessions []string
	for sessionID := range tenantClients {
		sessions = append(sessions, sessionID)
	}
	s.clients.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":        tenantID,
		"active_sessions":  sessions,
		"connection_count": connectionCount,
	})
}

func (s *StreamingService) broadcastToSessionHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	sessionID := c.Param("sessionId")

	var req struct {
		Type string      `json:"type" binding:"required"`
		Data interface{} `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message := BroadcastMessage{
		TenantID:  tenantID,
		SessionID: sessionID,
		Type:      req.Type,
		Data:      req.Data,
	}

	s.clients.broadcast <- message

	c.JSON(http.StatusOK, gin.H{
		"message": "Broadcast sent successfully",
		"sent_to": gin.H{
			"tenant_id":  tenantID,
			"session_id": sessionID,
			"type":       req.Type,
		},
	})
}

// Internal API handlers
func (s *StreamingService) handleLocationUpdate(c *gin.Context) {
	var req struct {
		TenantID  string  `json:"tenant_id" binding:"required"`
		SessionID string  `json:"session_id" binding:"required"`
		UserID    string  `json:"user_id" binding:"required"`
		Latitude  float64 `json:"latitude" binding:"required"`
		Longitude float64 `json:"longitude" binding:"required"`
		Accuracy  float64 `json:"accuracy"`
		Timestamp string  `json:"timestamp"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Broadcast location update to connected clients
	locationData := gin.H{
		"latitude":  req.Latitude,
		"longitude": req.Longitude,
		"accuracy":  req.Accuracy,
		"timestamp": req.Timestamp,
		"user_id":   req.UserID,
	}

	message := BroadcastMessage{
		TenantID:  req.TenantID,
		SessionID: req.SessionID,
		Type:      "location_update",
		Data:      locationData,
	}

	s.clients.broadcast <- message

	// Also send to third-party endpoints if configured
	go s.sendToThirdParty(req.TenantID, req.SessionID, locationData)

	c.JSON(http.StatusOK, gin.H{"message": "Location update processed"})
}

func (s *StreamingService) handleSessionEvent(c *gin.Context) {
	var req struct {
		TenantID  string `json:"tenant_id" binding:"required"`
		SessionID string `json:"session_id" binding:"required"`
		UserID    string `json:"user_id" binding:"required"`
		EventType string `json:"event_type" binding:"required"` // session_started, session_ended
		Data      gin.H  `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Broadcast session event to connected clients
	eventData := gin.H{
		"event_type": req.EventType,
		"user_id":    req.UserID,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	// Merge additional data
	for k, v := range req.Data {
		eventData[k] = v
	}

	message := BroadcastMessage{
		TenantID:  req.TenantID,
		SessionID: req.SessionID,
		Type:      req.EventType,
		Data:      eventData,
	}

	s.clients.broadcast <- message

	c.JSON(http.StatusOK, gin.H{"message": "Session event processed"})
}

// Background processor for location data
func (s *StreamingService) processLocationData() {
	// This would typically listen to a message queue or database changes
	// For now, we'll rely on the internal API calls from location service
	log.Println("Location data processor started")
}

// Third-party integration
func (s *StreamingService) sendToThirdParty(tenantID, sessionID string, data interface{}) {
	// Get third-party configuration for this tenant
	var streamingSession models.StreamingSession
	if err := s.db.Where("tenant_id = ? AND session_id = ?", tenantID, "default").
		First(&streamingSession).Error; err != nil {
		return // No third-party configuration
	}

	if streamingSession.ThirdPartyEndpoint == "" {
		return
	}

	// Prepare payload
	_ = gin.H{
		"tenant_id":  tenantID,
		"session_id": sessionID,
		"data":       data,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	// Send to third-party endpoint (simplified implementation)
	// In production, you would implement proper HTTP client with retries
	log.Printf("Sending data to third-party: %s", streamingSession.ThirdPartyEndpoint)
	// http.Post(streamingSession.ThirdPartyEndpoint, "application/json", ...)
}

// Middleware
func (s *StreamingService) tenantContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userTenantID := c.GetString("tenant_id")
		if userTenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *StreamingService) internalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simple internal authentication (in production, use proper service-to-service auth)
		authHeader := c.GetHeader("Authorization")
		if authHeader != "Internal-Service-Token" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Internal service authentication required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *StreamingService) corsMiddleware() gin.HandlerFunc {
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
