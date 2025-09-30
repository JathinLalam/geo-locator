package auth

import (
	"errors"
	"fmt"
	"geo-locator/pkg/config"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
)

type CognitoClient struct {
	client cognitoidentityprovideriface.CognitoIdentityProviderAPI
	config *config.Config
}

type AuthResult struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type UserAttributes struct {
	Email    string            `json:"email"`
	TenantID string            `json:"tenant_id"`
	Role     string            `json:"role"`
	Custom   map[string]string `json:"custom"`
}

func NewCognitoClient(cfg *config.Config) (*CognitoClient, error) {
	if cfg.CognitoUserPoolID == "" || cfg.CognitoAppClientID == "" {
		return nil, errors.New("cognito configuration is required")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(cfg.CognitoRegion),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	return &CognitoClient{
		client: cognitoidentityprovider.New(sess),
		config: cfg,
	}, nil
}

func (c *CognitoClient) SignUp(email, password, tenantID, role string) (string, error) {
	userAttributes := []*cognitoidentityprovider.AttributeType{
		{
			Name:  aws.String("email"),
			Value: aws.String(email),
		},
		{
			Name:  aws.String("custom:tenant_id"),
			Value: aws.String(tenantID),
		},
		{
			Name:  aws.String("custom:role"),
			Value: aws.String(role),
		},
		{
			Name:  aws.String("email_verified"),
			Value: aws.String("true"),
		},
	}

	input := &cognitoidentityprovider.SignUpInput{
		ClientId:       aws.String(c.config.CognitoAppClientID),
		Username:       aws.String(email),
		Password:       aws.String(password),
		UserAttributes: userAttributes,
	}

	result, err := c.client.SignUp(input)
	if err != nil {
		return "", fmt.Errorf("failed to sign up user: %w", err)
	}

	log.Printf("User %s signed up successfully", email)
	return *result.UserSub, nil
}

func (c *CognitoClient) SignIn(email, password string) (*AuthResult, error) {
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		ClientId: aws.String(c.config.CognitoAppClientID),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(email),
			"PASSWORD": aws.String(password),
		},
	}

	result, err := c.client.InitiateAuth(input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign in user: %w", err)
	}

	if result.AuthenticationResult == nil {
		return nil, errors.New("authentication result is nil")
	}

	authResult := &AuthResult{
		AccessToken:  *result.AuthenticationResult.AccessToken,
		IDToken:      *result.AuthenticationResult.IdToken,
		RefreshToken: *result.AuthenticationResult.RefreshToken,
		ExpiresIn:    *result.AuthenticationResult.ExpiresIn,
	}

	log.Printf("User %s signed in successfully", email)
	return authResult, nil
}

func (c *CognitoClient) RefreshToken(refreshToken string) (*AuthResult, error) {
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("REFRESH_TOKEN_AUTH"),
		ClientId: aws.String(c.config.CognitoAppClientID),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": aws.String(refreshToken),
		},
	}

	result, err := c.client.InitiateAuth(input)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	if result.AuthenticationResult == nil {
		return nil, errors.New("authentication result is nil")
	}

	return &AuthResult{
		AccessToken: *result.AuthenticationResult.AccessToken,
		IDToken:     *result.AuthenticationResult.IdToken,
		ExpiresIn:   *result.AuthenticationResult.ExpiresIn,
	}, nil
}

func (c *CognitoClient) GetUser(accessToken string) (*UserAttributes, error) {
	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(accessToken),
	}

	result, err := c.client.GetUser(input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	attributes := &UserAttributes{
		Custom: make(map[string]string),
	}

	for _, attr := range result.UserAttributes {
		switch *attr.Name {
		case "email":
			attributes.Email = *attr.Value
		case "custom:tenant_id":
			attributes.TenantID = *attr.Value
		case "custom:role":
			attributes.Role = *attr.Value
		default:
			if len(*attr.Name) > 7 && (*attr.Name)[:7] == "custom:" {
				attributes.Custom[(*attr.Name)[7:]] = *attr.Value
			}
		}
	}

	return attributes, nil
}

func (c *CognitoClient) ValidateToken(accessToken string) (*UserAttributes, error) {
	// For simplicity, we'll use GetUser to validate the token
	// In production, you might want to use JWT verification locally
	return c.GetUser(accessToken)
}
