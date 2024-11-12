package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shreeyash-ugale/go-sail-server/database"
	"github.com/shreeyash-ugale/go-sail-server/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type TokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func GenerateAPIKey(c *gin.Context) {
	var request TokenRequest
	var user models.User
	var apik models.APIKey
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	// check if email exists and password is correct
	filter := bson.M{"email": request.Email}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := database.UserCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		c.Abort()
		return
	}
	credentialError := user.CheckPassword(request.Password)
	if credentialError != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		c.Abort()
	}
	apiKey, err := genkey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	user.APIKey = append(user.APIKey, apiKey)
	_, err = database.UserCollection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"api_key": user.APIKey}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	apik.ID = primitive.NewObjectID()
	apik.Key = apiKey
	apik.UserID = user.ID
	apik.PlanID = user.PlanID
	_, err = database.APIKeyCollection.InsertOne(ctx, apik)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_key": apiKey})
}

func genkey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RevokeAPIKey(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
		Key   string `json:"key"`
	}
	var user models.User

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	// check if email exists
	filter := bson.M{"email": request.Email}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := database.UserCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		c.Abort()
		return
	}

	// remove the API key from user's APIKey slice
	for i, key := range user.APIKey {
		if key == request.Key {
			user.APIKey = append(user.APIKey[:i], user.APIKey[i+1:]...)
			break
		}
	}

	_, err = database.UserCollection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"api_key": user.APIKey}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	// delete the API key from APIKeyCollection
	_, err = database.APIKeyCollection.DeleteOne(ctx, bson.M{"key": request.Key})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted successfully"})
}
