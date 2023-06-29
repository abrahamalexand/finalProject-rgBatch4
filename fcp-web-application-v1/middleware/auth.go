package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		cookie, err := ctx.Request.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			if ctx.GetHeader("Content-Type") == "application/json" {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				ctx.Abort()
				return
			} else {
				ctx.Redirect(http.StatusSeeOther, "/login")
				ctx.Abort()
				return
			}

		}

		cookieValue := cookie.Value
		stdClaims := &model.Claims{}

		token, err := jwt.ParseWithClaims(cookieValue, stdClaims, func(token *jwt.Token) (interface{}, error) {
			// Provide the key used to sign the token.
			return model.JwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				ctx.JSON(http.StatusSeeOther, gin.H{"error": "Invalid token"})
				ctx.Abort()
				return
			} else {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
				ctx.Abort()
				return
			}

		}

		if !token.Valid {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()
			return
		}

		ctx.Set("email", stdClaims.Email)
		ctx.Next()
		// TODO: answer here
	})
}
