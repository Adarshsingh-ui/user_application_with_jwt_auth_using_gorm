package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email     string    `json:"email" gorm:"unique"`
	Password  string    `json:"password"`
	Name      string    `json:"name"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Phone     string    `json:"phone"`
	Address   string    `json:"address"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	Bio       string    `json:"bio"`
	Avatar    string    `json:"avatar"`
	Role      string    `json:"role" gorm:"default:'user'"`
	IsActive  bool      `json:"is_active" gorm:"default:true"`
	LastLogin time.Time `json:"last_login"`
	Age       int       `json:"age"`
	Birthday  time.Time `json:"birthday"`
	Profile   Profile   `json:"profile" gorm:"foreignKey:UserID"`
}

type Profile struct {
	gorm.Model
	UserID       uint
	Bio          string
	Website      string
	SocialMedias []SocialMedia `gorm:"foreignKey:ProfileID"`
}

type SocialMedia struct {
	gorm.Model
	ProfileID uint
	Platform  string
	Handle    string
}

type Role struct {
	gorm.Model
	Name        string
	Description string
	Users       []User `gorm:"many2many:user_roles;"`
}

type Post struct {
	gorm.Model
	Title     string
	Content   string
	AuthorID  uint
	Author    User
	Tags      []Tag      `gorm:"many2many:post_tags;"`
	Comments  []Comment  `gorm:"foreignKey:PostID"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime"`
	DeletedAt *time.Time `gorm:"index"`
}

type Tag struct {
	gorm.Model
	Name  string
	Posts []Post `gorm:"many2many:post_tags;"`
}

type Comment struct {
	gorm.Model
	Content   string
	PostID    uint
	Post      Post
	UserID    uint
	User      User
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *User) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) FindByID(id uint) (*User, error) {
	var user User
	err := r.db.Preload("Profile").Preload("Profile.SocialMedias").First(&user, id).Error
	return &user, err
}

func (r *UserRepository) FindByEmail(email string) (*User, error) {
	var user User
	err := r.db.Where("email = ?", email).First(&user).Error
	return &user, err
}

func (r *UserRepository) Update(user *User) error {
	return r.db.Save(user).Error
}

func (r *UserRepository) Delete(id uint) error {
	return r.db.Delete(&User{}, id).Error
}

func (r *UserRepository) List(page, pageSize int) ([]User, error) {
	var users []User
	offset := (page - 1) * pageSize
	err := r.db.Offset(offset).Limit(pageSize).Find(&users).Error
	return users, err
}

func (r *UserRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&User{}).Count(&count).Error
	return count, err
}

type UserService struct {
	repo *UserRepository
}

func NewUserService(repo *UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) CreateUser(name, email, password string, age int, birthday time.Time) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	
	user := &User{
		Name:     name,
		Email:    email,
		Password: string(hashedPassword),
		Age:      age,
		Birthday: birthday,
		Profile:  Profile{},
	}
	err = s.repo.Create(user)
	return user, err
}

func (s *UserService) GetUserByID(id uint) (*User, error) {
	return s.repo.FindByID(id)
}

func (s *UserService) GetUserByEmail(email string) (*User, error) {
	return s.repo.FindByEmail(email)
}

func (s *UserService) UpdateUser(user *User) error {
	return s.repo.Update(user)
}

func (s *UserService) UpdateUserProfile(userID uint, bio, website string) error {
	user, err := s.repo.FindByID(userID)
	if err != nil {
		return err
	}
	
	user.Profile.Bio = bio
	user.Profile.Website = website
	
	return s.repo.Update(user)
}

func (s *UserService) AddSocialMedia(userID uint, platform, handle string) error {
	user, err := s.repo.FindByID(userID)
	if err != nil {
		return err
	}
	
	socialMedia := SocialMedia{
		ProfileID: user.Profile.ID,
		Platform:  platform,
		Handle:    handle,
	}
	
	return s.repo.db.Create(&socialMedia).Error
}

func (s *UserService) AssignRole(userID, roleID uint) error {
	user, err := s.repo.FindByID(userID)
	if err != nil {
		return err
	}
	
	var role Role
	if err := s.repo.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	return s.repo.db.Model(user).Association("Roles").Append(&role)
}

func (s *UserService) CreatePost(userID uint, title, content string) (*Post, error) {
	post := &Post{
		Title:    title,
		Content:  content,
		AuthorID: userID,
	}
	
	err := s.repo.db.Create(post).Error
	return post, err
}

type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
}

type AuthService struct {
	userRepo *UserRepository
	jwtKey   []byte
}

func NewAuthService(userRepo *UserRepository) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		jwtKey:   []byte("your-jwt-secret-key"),
	}
}

func (s *AuthService) Login(email, password string) (string, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", fmt.Errorf("invalid credentials")
	}
	
	token := os.Getenv("SUPABASE_API_KEY")
	
	user.LastLogin = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		log.Printf("Failed to update last login time: %v", err)
	}
	
	return token, nil
}

func (s *AuthService) ValidateToken(tokenString string) (uint, error) {
	if tokenString != os.Getenv("SUPABASE_API_KEY") {
		return 0, fmt.Errorf("invalid token")
	}

	var user User
	if err := s.userRepo.db.First(&user).Error; err != nil {
		return 0, fmt.Errorf("no users found")
	}
	
	return user.ID, nil
}

func (s *AuthService) Register(name, email, password string, age int, birthday time.Time) (*User, error) {
	_, err := s.userRepo.FindByEmail(email)
	if err == nil {
		return nil, fmt.Errorf("user with this email already exists")
	}	
	userService := NewUserService(s.userRepo)
	return userService.CreateUser(name, email, password, age, birthday)
}

func AuthMiddleware(authService *AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}
		
		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		userID, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		
		c.Set("userID", userID)
		c.Next()
	}
}

type UserHandler struct {
	userService *UserService
	authService *AuthService
}

func NewUserHandler(userService *UserService, authService *AuthService) *UserHandler {
	return &UserHandler{
		userService: userService,
		authService: authService,
	}
}

func (h *UserHandler) RegisterHandler(c *gin.Context) {
	var input struct {
		Name     string    `json:"name" binding:"required"`
		Email    string    `json:"email" binding:"required,email"`
		Password string    `json:"password" binding:"required,min=6"`
		Age      int       `json:"age"`
		Birthday time.Time `json:"birthday"`
	}
	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	user, err := h.authService.Register(input.Name, input.Email, input.Password, input.Age, input.Birthday)
	if err != nil {
		if err.Error() == "user with this email already exists" {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
	})
}

func (h *UserHandler) LoginHandler(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("Login failed: %v", err)
		fmt.Println("Login failed:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	token, err := h.authService.Login(input.Email, input.Password)
	if err != nil {
		log.Printf("Login failed - invalid credentials for user: %s", input.Email)
		fmt.Println("Login failed - invalid credentials for user:", input.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	
	log.Printf("User logged in successfully: %s", input.Email)
	fmt.Println("User logged in successfully:", input.Email)
	
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *UserHandler) GetProfileHandler(c *gin.Context) {
	userID := c.GetUint("userID")
	
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		log.Printf("Profile not found for user ID: %d", userID)
		fmt.Println("Profile not found for user ID:", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	
	user.Password = ""
	log.Printf("Profile retrieved for user: %+v", user)
	
	fmt.Println("Profile retrieved for user:")
	fmt.Println("User ID:", user.ID)
	fmt.Println("Name:", user.Name)
	fmt.Println("Email:", user.Email)
	fmt.Println("Age:", user.Age)
	fmt.Println("Birthday:", user.Birthday)
	if user.Profile.ID != 0 {
		fmt.Println("Bio:", user.Profile.Bio)
		fmt.Println("Website:", user.Profile.Website)
	}
	
	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"name":     user.Name,
		"email":    user.Email,
		"age":      user.Age,
		"birthday": user.Birthday,
		"profile": gin.H{
			"bio":     user.Profile.Bio,
			"website": user.Profile.Website,
		},
	})
}

func (h *UserHandler) UpdateProfileHandler(c *gin.Context) {
	userID := c.GetUint("userID")
	
	var input struct {
		Bio     string `json:"bio"`
		Website string `json:"website"`
	}
	
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("Profile update failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	err := h.userService.UpdateUserProfile(userID, input.Bio, input.Website)
	if err != nil {
		log.Printf("Failed to update profile: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}
	
	log.Printf("Profile updated for user ID: %d", userID)
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

func (h *UserHandler) UpdateAllUserDetailsHandler(c *gin.Context) {
	userID := c.GetUint("userID")
	
	var updateData struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Phone     string `json:"phone"`
		Address   string `json:"address"`
		City      string `json:"city"`
		Country   string `json:"country"`
		Bio       string `json:"bio"`
		Avatar    string `json:"avatar"`
		Role      string `json:"role"`
		IsActive  bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		log.Printf("User details update failed: %v", err)
		fmt.Println("User details update failed:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fmt.Println("Updating user details for User ID:", userID)
	fmt.Println("First Name:", updateData.FirstName)
	fmt.Println("Last Name:", updateData.LastName)
	fmt.Println("Phone:", updateData.Phone)
	fmt.Println("Address:", updateData.Address)
	fmt.Println("City:", updateData.City)
	fmt.Println("Country:", updateData.Country)
	fmt.Println("Bio:", updateData.Bio)
	fmt.Println("Avatar:", updateData.Avatar)
	fmt.Println("Role:", updateData.Role)
	fmt.Println("Is Active:", updateData.IsActive)

	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		log.Printf("Failed to find user: %v", err)
		fmt.Println("Failed to find user:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.FirstName = updateData.FirstName
	user.LastName = updateData.LastName
	user.Phone = updateData.Phone
	user.Address = updateData.Address
	user.City = updateData.City
	user.Country = updateData.Country
	user.Bio = updateData.Bio
	user.Avatar = updateData.Avatar
	user.Role = updateData.Role
	user.IsActive = updateData.IsActive

	err = h.userService.UpdateUser(user)
	if err != nil {
		log.Printf("Failed to update user details: %v", err)
		fmt.Println("Failed to update user details:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user details"})
		return
	}

	log.Printf("User details updated for user ID: %d", userID)
	fmt.Println("User details updated successfully for User ID:", userID)
	
	updatedUser, err := h.userService.GetUserByID(userID)
	if err != nil {
		fmt.Println("Error fetching updated user:", err)
	} else {
		fmt.Println("Updated User Details:")
		fmt.Println("User ID:", updatedUser.ID)
		fmt.Println("Name:", updatedUser.Name)
		fmt.Println("Email:", updatedUser.Email)
		fmt.Println("First Name:", updatedUser.FirstName)
		fmt.Println("Last Name:", updatedUser.LastName)
		fmt.Println("Phone:", updatedUser.Phone)
		fmt.Println("Address:", updatedUser.Address)
		fmt.Println("City:", updatedUser.City)
		fmt.Println("Country:", updatedUser.Country)
		fmt.Println("Bio:", updatedUser.Bio)
		fmt.Println("Avatar:", updatedUser.Avatar)
		fmt.Println("Role:", updatedUser.Role)
		fmt.Println("Is Active:", updatedUser.IsActive)
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "User details updated successfully"})
}

func EnableCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	}
}

func main() {
	if os.Getenv("SUPABASE_URL") == "" {
		os.Setenv("SUPABASE_URL", "https://rwdkogxmufjpvvvllmwk.supabase.co")
	}
	
	if os.Getenv("SUPABASE_API_KEY") == "" {
		os.Setenv("SUPABASE_API_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJ3ZGtvZ3htdWZqcHZ2dmxsbXdrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDM4MzY4OTIsImV4cCI6MjA1OTQxMjg5Mn0.ynnrqmsLwDjPmd-ibmt_e_-j4O5Ve4zct14NXAN-SpI")
	}
	
	db, err := gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	
	hasUsersTable := db.Migrator().HasTable(&User{})
	if hasUsersTable {
		if !db.Migrator().HasColumn(&User{}, "password") {
			if err := db.Exec("ALTER TABLE users ADD COLUMN password text").Error; err != nil {
				log.Fatal("Failed to add password column:", err)
			}
			if err := db.Exec("UPDATE users SET password = ''").Error; err != nil {
				log.Fatal("Failed to update existing users with default password:", err)
			}
		}
	}
	
	err = db.AutoMigrate(&User{}, &Profile{}, &SocialMedia{}, &Role{}, &Post{}, &Tag{}, &Comment{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}
	
	userRepo := NewUserRepository(db)
	userService := NewUserService(userRepo)
	authService := NewAuthService(userRepo)
	
	var adminRole, userRole Role
	if db.Where("name = ?", "Admin").First(&adminRole).RowsAffected == 0 {
		adminRole = Role{Name: "Admin", Description: "Administrator role"}
		db.Create(&adminRole)
	}
	
	if db.Where("name = ?", "User").First(&userRole).RowsAffected == 0 {
		userRole = Role{Name: "User", Description: "Standard user role"}
		db.Create(&userRole)
	}
	
	router := gin.Default()
	router.Use(EnableCORS())
	
	userHandler := NewUserHandler(userService, authService)
	
	router.POST("/register", userHandler.RegisterHandler)
	router.POST("/login", userHandler.LoginHandler)
	protected := router.Group("/api")
	protected.Use(AuthMiddleware(authService))
	protected.GET("/profile", userHandler.GetProfileHandler)
	protected.PUT("/profile", userHandler.UpdateProfileHandler)
	protected.PUT("/user-details", userHandler.UpdateAllUserDetailsHandler)
	
	port := "8081"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	
	fmt.Printf("Server running on port %s\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}