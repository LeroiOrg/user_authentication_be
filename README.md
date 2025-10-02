# User Authentication Service

FastAPI-based microservice providing complete user authentication with JWT, email verification, 2FA, and user credit management.

## 🚀 Features

- ✅ User registration with email verification
- ✅ Email/password and Google OAuth login  
- ✅ Two-factor authentication (2FA)
- ✅ JWT token authentication
- ✅ Password recovery
- ✅ User profile management
- ✅ Credit system
- ✅ bcrypt password encryption

## 🛠️ Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy
- **Authentication**: JWT + bcrypt
- **Containerization**: Docker & Docker Compose
- **Email**: FastAPI-Mail



### 1. Clone and setup
```bash
git clone https://github.com/LeroiOrg/user_authentication_be.git
cd user_authentication_be
```

### 2. Environment variables
Create `.env` file:

### 3. Run with Docker
```bash
# First time (build images)
docker-compose up --build

# Normal run
docker-compose up

# Stop services
docker-compose down
```

### 4. Access the service
- **API**: http://localhost:8001
- **Swagger Docs**: http://localhost:8001/docs
- **Database**: localhost:5433

## 📚 Main API Endpoints

### Authentication
```http
POST /users_authentication_path/register
POST /users_authentication_path/login
POST /users_authentication_path/login-google
GET  /users_authentication_path/validate-token
```

### User Management
```http
GET  /users_authentication_path/user-profile
PUT  /users_authentication_path/update-user
DELETE /users_authentication_path/delete-user/{email}
```

### Email & Verification
```http
POST /users_authentication_path/send-verification
POST /users_authentication_path/verify-code
POST /users_authentication_path/forgot-password
POST /users_authentication_path/reset-password
```

### Credits System
```http
GET   /users_authentication_path/user-credits/{email}
PATCH /users_authentication_path/user-credits/{email}
```

## 🐳 Docker Services

1. **db_user_authentication**: PostgreSQL (port 5433)
2. **migrations_user_authentication**: Database migrations
3. **user_authentication_service**: FastAPI app (port 8001)
