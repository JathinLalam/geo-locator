package monitoring

import (
	"expvar"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Metrics struct {
	Requests       *expvar.Int
	Errors         *expvar.Int
	ResponseTime   *expvar.Int
	ActiveSessions *expvar.Int
	WebSocketConns *expvar.Int
}

func NewMetrics() *Metrics {
	return &Metrics{
		Requests:       expvar.NewInt("requests_total"),
		Errors:         expvar.NewInt("errors_total"),
		ResponseTime:   expvar.NewInt("response_time_ms"),
		ActiveSessions: expvar.NewInt("active_sessions"),
		WebSocketConns: expvar.NewInt("websocket_connections"),
	}
}

func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		m.Requests.Add(1)
		m.ResponseTime.Set(duration.Milliseconds())

		if c.Writer.Status() >= 400 {
			m.Errors.Add(1)
		}
	}
}

func (m *Metrics) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"requests_total":        m.Requests.Value(),
			"errors_total":          m.Errors.Value(),
			"response_time_ms":      m.ResponseTime.Value(),
			"active_sessions":       m.ActiveSessions.Value(),
			"websocket_connections": m.WebSocketConns.Value(),
			"timestamp":             time.Now().Format(time.RFC3339),
		})
	}
}
