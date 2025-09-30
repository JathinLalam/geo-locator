package main

import (
	"geo-locator/internal/auth"
	"geo-locator/pkg/config"
	"geo-locator/pkg/middleware"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type APIGateway struct {
	cognitoClient  *auth.CognitoClient
	authMiddleware *middleware.AuthMiddleware
	serviceRoutes  map[string]string
}

func main() {
	cfg := config.Load()

	// Initialize Cognito client
	cognitoClient, err := auth.NewCognitoClient(cfg)
	if err != nil {
		log.Printf("Warning: Cognito client initialization failed: %v", err)
	}

	authMiddleware := middleware.NewAuthMiddleware(cognitoClient)

	gateway := &APIGateway{
		cognitoClient:  cognitoClient,
		authMiddleware: authMiddleware,
		serviceRoutes: map[string]string{
			"auth":      "http://localhost:8080",
			"tenant":    "http://localhost:8081",
			"location":  "http://localhost:8082",
			"streaming": "http://localhost:8083",
		},
	}

	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Global middleware
	router.Use(gateway.corsMiddleware())
	//router.Use(gateway.rateLimitMiddleware())
	router.Use(gateway.loggingMiddleware())

	// Health check (aggregated)
	router.GET("/health", gateway.healthCheckHandler)

	// Public routes
	public := router.Group("/api/v1")
	{
		public.POST("/auth/login", gateway.reverseProxy("auth", "/auth/login"))
		public.POST("/auth/register", gateway.reverseProxy("auth", "/auth/register"))
	}

	// Protected routes
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware.Authenticate())
	{
		// Auth service routes
		protected.POST("/auth/refresh", gateway.reverseProxy("auth", "/auth/refresh"))
		protected.POST("/auth/validate", gateway.reverseProxy("auth", "/auth/validate"))
		protected.GET("/auth/profile", gateway.reverseProxy("auth", "/auth/profile"))

		// Tenant service routes
		protected.GET("/tenants", gateway.reverseProxy("tenant", "/api/v1/tenants"))
		protected.POST("/tenants", gateway.reverseProxy("tenant", "/api/v1/tenants"))
		protected.GET("/tenants/:id", gateway.reverseProxy("tenant", "/api/v1/tenants/:id"))
		protected.PUT("/tenants/:id", gateway.reverseProxy("tenant", "/api/v1/tenants/:id"))
		protected.DELETE("/tenants/:id", gateway.reverseProxy("tenant", "/api/v1/tenants/:id"))
		protected.GET("/tenants/:id/stats", gateway.reverseProxy("tenant", "/api/v1/tenants/:id/stats"))
		protected.GET("/tenant-users", gateway.reverseProxy("tenant", "/api/v1/tenant-users"))
		protected.POST("/tenant-users", gateway.reverseProxy("tenant", "/api/v1/tenant-users"))
		protected.PUT("/tenant-users/:userId", gateway.reverseProxy("tenant", "/api/v1/tenant-users/:userId"))
		protected.DELETE("/tenant-users/:userId", gateway.reverseProxy("tenant", "/api/v1/tenant-users/:userId"))
		protected.GET("/tenant-config", gateway.reverseProxy("tenant", "/api/v1/tenant-config"))
		protected.PUT("/tenant-config", gateway.reverseProxy("tenant", "/api/v1/tenant-config"))

		// Location service routes
		protected.POST("/sessions", gateway.reverseProxy("location", "/api/v1/sessions"))
		protected.GET("/sessions", gateway.reverseProxy("location", "/api/v1/sessions"))
		protected.GET("/sessions/:sessionId", gateway.reverseProxy("location", "/api/v1/sessions/:sessionId"))
		protected.DELETE("/sessions/:sessionId", gateway.reverseProxy("location", "/api/v1/sessions/:sessionId"))
		protected.POST("/locations/:sessionId", gateway.reverseProxy("location", "/api/v1/locations/:sessionId"))
		protected.GET("/locations/:sessionId/points", gateway.reverseProxy("location", "/api/v1/locations/:sessionId/points"))
		protected.GET("/session-status/:sessionId", gateway.reverseProxy("location", "/api/v1/session-status/:sessionId"))

		// Streaming service routes
		protected.POST("/streaming/config", gateway.reverseProxy("streaming", "/api/v1/streaming/config"))
		protected.GET("/streaming/config", gateway.reverseProxy("streaming", "/api/v1/streaming/config"))
		protected.GET("/streaming/connections", gateway.reverseProxy("streaming", "/api/v1/streaming/connections"))
		protected.POST("/streaming/broadcast/:sessionId", gateway.reverseProxy("streaming", "/api/v1/streaming/broadcast/:sessionId"))
	}

	// WebSocket routes (special handling)
	router.GET("/ws/third-party", gateway.websocketProxy("streaming", "/ws/third-party"))
	router.GET("/api/v1/ws/session/:sessionId", gateway.websocketProxy("streaming", "/api/v1/ws/session/:sessionId"))

	log.Printf("API Gateway starting on port %s", cfg.ServerPort)
	log.Fatal(router.Run(":" + cfg.ServerPort))
}

func (g *APIGateway) reverseProxy(service, path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL, ok := g.serviceRoutes[service]
		if !ok {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Service not available"})
			return
		}

		remote, err := url.Parse(serviceURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(remote)

		// Modify request
		proxy.Director = func(req *http.Request) {
			req.Header = c.Request.Header.Clone()
			req.Host = remote.Host
			req.URL.Scheme = remote.Scheme
			req.URL.Host = remote.Host
			req.URL.Path = singleJoiningSlash(remote.Path, path)

			// Replace path parameters
			for _, param := range c.Params {
				req.URL.Path = strings.Replace(req.URL.Path, ":"+param.Key, param.Value, 1)
			}

			// Add tenant context headers for internal services
			if tenantID := c.GetString("tenant_id"); tenantID != "" {
				req.Header.Set("X-Tenant-ID", tenantID)
			}
			if userID := c.GetString("user_id"); userID != "" {
				req.Header.Set("X-User-ID", userID)
			}
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func (g *APIGateway) websocketProxy(service, path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// WebSocket connections are passed through directly
		// In production, you might want to add WebSocket-specific authentication
		serviceURL, ok := g.serviceRoutes[service]
		if !ok {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Service not available"})
			return
		}

		targetURL := serviceURL + path
		http.Redirect(c.Writer, c.Request, targetURL, http.StatusTemporaryRedirect)
	}
}

func (g *APIGateway) healthCheckHandler(c *gin.Context) {
	healthStatus := gin.H{
		"status":   "healthy",
		"gateway":  "ok",
		"services": gin.H{},
	}

	// Check health of all services
	client := &http.Client{Timeout: 5 * time.Second}
	for service, url := range g.serviceRoutes {
		resp, err := client.Get(url + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			healthStatus["services"].(gin.H)[service] = "unhealthy"
			healthStatus["status"] = "degraded"
		} else {
			healthStatus["services"].(gin.H)[service] = "healthy"
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	statusCode := http.StatusOK
	if healthStatus["status"] == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, healthStatus)
}

// Enhanced rate limiting middleware
//func (g *APIGateway) rateLimitMiddleware() gin.HandlerFunc {
//	// In production, use Redis for distributed rate limiting
//	limiter := make(map[string]*rate.Limiter)
//	var mu sync.Mutex
//
//	return func(c *gin.Context) {
//		clientIP := c.ClientIP()
//		tenantID := c.GetString("tenant_id")
//
//		// Use tenant-specific limits if available, otherwise IP-based
//		key := clientIP
//		if tenantID != "" {
//			key = tenantID
//		}
//
//		mu.Lock()
//		if limiter[key] == nil {
//			// Default: 100 requests per minute per tenant/IP
//			limiter[key] = rate.NewLimiter(100, 100)
//		}
//		mu.Unlock()
//
//		if !limiter[key].Allow() {
//			c.JSON(http.StatusTooManyRequests, gin.H{
//				"error":       "Rate limit exceeded",
//				"retry_after": "60 seconds",
//			})
//			c.Abort()
//			return
//		}
//
//		c.Next()
//	}
//}

// Enhanced logging middleware
func (g *APIGateway) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Log request details
		duration := time.Since(start)
		tenantID := c.GetString("tenant_id")
		userID := c.GetString("user_id")

		log.Printf("[API-Gateway] %s %s %d %v tenant=%s user=%s",
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			duration,
			tenantID,
			userID,
		)
	}
}

func (g *APIGateway) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Helper function
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
