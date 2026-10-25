package providers

import "context"

// Message represents a single message sent to an AI model.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Response struct {
	Content string `json:"content"`
}

type Provider interface {
	Name() string
	Generate(ctx context.Context, request Request) (Response, error)
}
