package middlewares

import (
	"github.com/shreeyash-ugale/go-sail-server/auth"
	"github.com/shreeyash-ugale/go-sail-server/database"
	"github.com/shreeyash-ugale/go-sail-server/models"

	"github.com/gin-gonic/gin"
)

func Auth() gin.HandlerFunc {
	return func(context *gin.Context) {
		var requestBody struct {
			APIKey string `json:"api_key"`
			Email  string `json:"email"`
		}

		if err := context.ShouldBindJSON(&requestBody); err != nil {
			context.JSON(400, gin.H{"error": "invalid request body"})
			context.Abort()
			return
		}

		var result models.User
		err = database.Instance.FindOne(context, bson.M{"email": requestBody.Email}).Decode(&result)
		if err != nil {
			context.JSON(401, gin.H{"error": "unauthorized"})
			context.Abort()
			return
		}

		for _, key := range result.APIKey {
			if key == requestBody.APIKey {
				context.Set("user", result)
		context.Next()
	}
}
