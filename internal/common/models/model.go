package models

import (
	"time"

	"gorm.io/gorm"
)

type BaseModel struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// BeforeCreate hook to set UUID and timestamps
func (b *BaseModel) BeforeCreate(tx *gorm.DB) error {
	b.CreatedAt = time.Now()
	b.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook
func (b *BaseModel) BeforeUpdate(tx *gorm.DB) error {
	b.UpdatedAt = time.Now()
	return nil
}

type Tenant struct {
	BaseModel
	Name   string `gorm:"not null;size:255" json:"name"`
	Domain string `gorm:"unique;not null;size:255" json:"domain"`
	Config JSONB  `gorm:"type:jsonb" json:"config"`

	// Relationships
	Users             []User               `gorm:"foreignKey:TenantID" json:"users,omitempty"`
	Configurations    *TenantConfiguration `gorm:"foreignKey:TenantID" json:"configuration,omitempty"`
	LocationData      []LocationData       `gorm:"foreignKey:TenantID" json:"-"`
	StreamingSessions []StreamingSession   `gorm:"foreignKey:TenantID" json:"-"`
	SessionMetadata   []SessionMetadata    `gorm:"foreignKey:TenantID" json:"-"`
}

type TenantConfiguration struct {
	BaseModel
	TenantID               string `gorm:"type:uuid;not null;uniqueIndex" json:"tenant_id"`
	MaxUsers               int    `gorm:"default:100" json:"max_users"`
	MaxSessionsPerUser     int    `gorm:"default:5" json:"max_sessions_per_user"`
	LocationUpdateInterval int    `gorm:"default:30" json:"location_update_interval"` // seconds
	DataRetentionDays      int    `gorm:"default:30" json:"data_retention_days"`
	Features               JSONB  `gorm:"type:jsonb;default:'[]'" json:"features"`

	// Relationships
	Tenant Tenant `gorm:"foreignKey:TenantID" json:"-"`
}

type User struct {
	BaseModel
	TenantID      string `gorm:"type:uuid;not null;index" json:"tenant_id"`
	CognitoUserID string `gorm:"unique;not null;size:255" json:"cognito_user_id"`
	Email         string `gorm:"not null;size:255" json:"email"`
	Role          string `gorm:"default:user;size:50" json:"role"` // user, admin

	// Relationships
	Tenant            Tenant             `gorm:"foreignKey:TenantID" json:"-"`
	LocationData      []LocationData     `gorm:"foreignKey:UserID" json:"-"`
	StreamingSessions []StreamingSession `gorm:"foreignKey:UserID" json:"-"`
	SessionMetadata   []SessionMetadata  `gorm:"foreignKey:UserID" json:"-"`
}

type SessionMetadata struct {
	BaseModel
	TenantID    string     `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID      string     `gorm:"type:uuid;not null;index" json:"user_id"`
	SessionID   string     `gorm:"not null;size:255;index" json:"session_id"`
	Status      string     `gorm:"default:active;size:50;index" json:"status"` // active, paused, completed
	StartedAt   time.Time  `gorm:"default:CURRENT_TIMESTAMP" json:"started_at"`
	EndedAt     *time.Time `json:"ended_at"`
	TotalPoints int        `gorm:"default:0" json:"total_points"`

	// Relationships
	User         User           `gorm:"foreignKey:UserID" json:"-"`
	LocationData []LocationData `gorm:"foreignKey:SessionID;references:SessionID" json:"location_data,omitempty"`
}

type LocationData struct {
	BaseModel
	TenantID  string    `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"user_id"`
	SessionID string    `gorm:"not null;size:255;index" json:"session_id"`
	Latitude  float64   `gorm:"type:decimal(10,8);not null" json:"latitude"`
	Longitude float64   `gorm:"type:decimal(11,8);not null" json:"longitude"`
	Accuracy  float64   `gorm:"type:decimal(5,2)" json:"accuracy"`
	Timestamp time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"timestamp"`

	// Relationships
	User    User            `gorm:"foreignKey:UserID" json:"-"`
	Session SessionMetadata `gorm:"foreignKey:SessionID;references:SessionID" json:"-"`
}

type StreamingSession struct {
	BaseModel
	TenantID           string     `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID             string     `gorm:"type:uuid;not null;index" json:"user_id"`
	SessionID          string     `gorm:"not null;size:255;index" json:"session_id"`
	ThirdPartyEndpoint string     `gorm:"size:500" json:"third_party_endpoint"`
	Status             string     `gorm:"default:active;size:50;index" json:"status"` // active, paused, completed
	StartedAt          time.Time  `gorm:"default:CURRENT_TIMESTAMP" json:"started_at"`
	EndedAt            *time.Time `json:"ended_at"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

type RateLimit struct {
	BaseModel
	TenantID     string    `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID       *string   `gorm:"type:uuid;index" json:"user_id"` // nullable for tenant-level limits
	Endpoint     string    `gorm:"not null;size:255" json:"endpoint"`
	RequestCount int       `gorm:"default:0" json:"request_count"`
	WindowStart  time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

type AuditLog struct {
	BaseModel
	TenantID     string  `gorm:"type:uuid;not null;index" json:"tenant_id"`
	UserID       *string `gorm:"type:uuid;index" json:"user_id"` // nullable for system actions
	Action       string  `gorm:"not null;size:255" json:"action"`
	ResourceType string  `gorm:"not null;size:100" json:"resource_type"`
	ResourceID   *string `gorm:"size:255" json:"resource_id"`
	Details      JSONB   `gorm:"type:jsonb" json:"details"`
	IPAddress    string  `gorm:"type:inet" json:"ip_address"`
	UserAgent    string  `gorm:"type:text" json:"user_agent"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

// JSONB type for handling PostgreSQL JSONB fields
type JSONB map[string]interface{}

func (j JSONB) GormDataType() string {
	return "jsonb"
}

// Value implements the driver.Valuer interface
func (j JSONB) Value() (interface{}, error) {
	if j == nil {
		return nil, nil
	}
	return j, nil
}

// Scan implements the sql.Scanner interface
func (j *JSONB) Scan(value interface{}) error {
	*j = make(JSONB)
	// Implementation would parse the value into the map
	return nil
}
