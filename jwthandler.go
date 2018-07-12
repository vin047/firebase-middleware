package firebasemiddleware

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"

	"google.golang.org/api/option"
)

type contextKey string

var (
	errLogger           = log.New(os.Stderr, "[ERROR] firebase-middleware-jwthandler: ", log.LstdFlags|log.Lshortfile)
	contextKeyAuthtoken = contextKey("auth-token")
)

// JWTHandler returns a router middleware for JWT token verification using the Firebase SDK
func JWTHandler(credentialsFilePath string) func(next http.Handler) http.Handler {
	// initialise sdk
	opt := option.WithCredentialsFile(credentialsFilePath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		errLogger.Fatalf("error initializing app: %v\n", err)
	}

	// get auth client
	client, err := app.Auth(context.Background())
	if err != nil {
		errLogger.Fatalf("error getting Auth client: %v\n", err)
	}

	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token := verifyRequest(ctx, client, r)
			ctx = context.WithValue(ctx, contextKeyAuthtoken, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

// verifyRequest extracts and verifies token
func verifyRequest(ctx context.Context, client *auth.Client, r *http.Request) *auth.Token {
	token, err := client.VerifyIDToken(ctx, tokenFromHeader(r))
	if err != nil {
		errLogger.Panicf("error verifying ID token: %v\n", err)
	}
	return token
}

// tokenFromHeader tries to retreive the token string from the "Authorization"
// reqeust header in the format "Authorization: Bearer TOKEN"
func tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// AuthToken gets the auth token from the context
func AuthToken(ctx context.Context) (string, bool) {
	tokenStr, ok := ctx.Value(contextKeyAuthtoken).(string)
	return tokenStr, ok
}
