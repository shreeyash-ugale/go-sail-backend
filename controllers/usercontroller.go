package controllers

import (
	"context"
	"net/http"

	"github.com/shreeyash-ugale/go-sail-server/database"
	"github.com/shreeyash-ugale/go-sail-server/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
)

func Signup(c *gin.Context) {
	var user models.User
	if c.ContentType() != "application/json" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request content type must be application/json"})
		return
	}

	var reqBody struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Plan     string `json:"plan"`
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingUser models.User
	err := database.UserCollection.FindOne(context.TODO(), bson.M{"email": reqBody.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email already exists"})
		return
	} else if err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var plan models.Plan
	filter := bson.M{"name": reqBody.Plan}
	err = database.PlanCollection.FindOne(context.TODO(), filter).Decode(&plan)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	user.Password = HashPassword([]byte(reqBody.Password))
	user.Email = reqBody.Email
	user.Username = reqBody.Username
	user.PlanID = plan.ID
	user.ID = primitive.NewObjectID()
	plan.Users = append(plan.Users, user.ID)

	// Save the user to the database
	_, err = database.UserCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update the plan with the new user
	_, err = database.PlanCollection.UpdateOne(context.TODO(), bson.M{"_id": plan.ID}, bson.M{"$set": bson.M{"users": plan.Users}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func UpgradePlan(c *gin.Context) {
	if c.ContentType() != "application/json" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request content type must be application/json"})
		return
	}

	var reqBody struct {
		Email    string `json:"email"`
		PlanName string `json:"plan_name"`
		Master   string `json:"master"`
	}
	if reqBody.Master != "9999" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You are not authorized to upgrade plan"})
		return
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := database.UserCollection.FindOne(context.TODO(), bson.M{"email": reqBody.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Find the new plan by name
	var newPlan models.Plan
	err = database.PlanCollection.FindOne(context.TODO(), bson.M{"name": reqBody.PlanName}).Decode(&newPlan)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update the user's plan
	user.PlanID = newPlan.ID
	_, err = database.UserCollection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"plan_id": newPlan.ID}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update the plan with the new user
	newPlan.Users = append(newPlan.Users, user.ID)
	_, err = database.PlanCollection.UpdateOne(context.TODO(), bson.M{"_id": newPlan.ID}, bson.M{"$set": bson.M{"users": newPlan.Users}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plan upgraded successfully"})
}

func HashPassword(password []byte) string {
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashedPassword)
}
