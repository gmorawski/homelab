#!/usr/bin/env python3
"""
Secure API REST with FastAPI - Build a Menu

"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import secrets
import logging
from enum import Enum
import socket

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = secrets.token_urlsafe(32)  # Generate an unique secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialisation FastAPI
app = FastAPI(
    title="API Menu Interactif FastAPI",
    description="Secure REST API with Q&A",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Middleware CORS for network access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    client_ip = request.client.host
    
    # Retrieve real IP if behind a proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = forwarded_for.split(",")[0].strip() if forwarded_for else client_ip
    
    logger.info(f" {request.method} {request.url.path} - IP: {real_ip}")
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    logger.info(f" Response {response.status_code} - Time: {process_time:.3f}s")
    
    return response

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class UserLogin(BaseModel):
    username: str
    password: str

class QuestionRequest(BaseModel):
    question_id: str
    parameters: Optional[Dict[str, Any]] = {}

class MenuCategory(str, Enum):
    SYSTEM = "system"
    SERVICES = "services"
    HELP = "help"
    ADMIN = "admin"

class ApiResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str

# User's database (for demo purposes)
# In production, use a real database
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
        "role": "admin",
        "created_at": "2024-01-01T00:00:00Z"
    },
    "user": {
        "username": "user",
        "hashed_password": pwd_context.hash("user123"),
        "role": "user",
        "created_at": "2024-01-01T00:00:00Z"
    }
}

# Structure menu
MENU_STRUCTURE = {
    "api_info": {
        "title": "API Menu Interactif FastAPI",
        "version": "1.0.0",
        "framework": "FastAPI",
        "description": "Secure REST API with Q&A"
    },
    "endpoints": {
        "authentication": {
            "POST /auth/login": "Please login to get a JWT token",
            "POST /auth/refresh": "Refresh your JWT token"
        },
        "menu": {
            "GET /": "Welcome page with basic info",
            "GET /info": "Get the full API menu (auth required)",
            "GET /menu/categories": "List available question categories"
        },
        "questions": {
            "POST /ask": "Ask a question by ID",
            "GET /questions/list": "List all available questions",
            "GET /question/{question_id}": "Ask a question directly by ID"
        },
        "system": {
            "GET /health": "Health check of the API",
            "GET /network": "Network connectivity info"
        }
    },
    "categories": {
        MenuCategory.SYSTEM: {
            "description": "Status and system information",
            "questions": ["server_status", "system_time", "api_health", "server_info"]
        },
        MenuCategory.SERVICES: {
            "description": "Services and fonctionnalities",
            "questions": ["service_list", "service_status", "uptime", "performance"]
        },
        MenuCategory.HELP: {
            "description": "Help and documentation",
            "questions": ["how_to_use", "api_documentation", "contact_support", "faq"]
        },
        MenuCategory.ADMIN: {
            "description": "Administration (Admin only)",
            "questions": ["user_stats", "system_logs", "config_info", "security_status"]
        }
    },
    "security_info": {
        "authentication_required": True,
        "token_type": "Bearer JWT",
        "token_expiry_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "encryption": "bcrypt",
        "algorithm": ALGORITHM
    }
}

# Answers to questions
def get_question_responses():
    """Generate dynamic responses for questions"""
    server_ips = get_server_ips()
    current_time = datetime.now()
    
    return {
        "server_status": {
            "response": "Server operational",
            "details": {
                "status": "healthy",
                "load": "normal",
                "uptime": "99.9%",
                "server_ips": server_ips,
                "port": 8000
            }
        },
        "system_time": {
            "response": f"System hour : {current_time.strftime('%Y-%m-%d %H:%M:%S')}",
            "details": {
                "iso_format": current_time.isoformat(),
                "timestamp": current_time.timestamp(),
                "timezone": "UTC",
                "format": "ISO 8601"
            }
        },
        "api_health": {
            "response": "API FastAPI healthy",
            "details": {
                "framework": "FastAPI",
                "version": "1.0.0",
                "database": "In-memory",
                "cache": "active",
                "services": "operational"
            }
        },
        "server_info": {
            "response": "Server information",
            "details": {
                "hostname": socket.gethostname(),
                "server_ips": server_ips,
                "port": 8000,
                "protocol": "HTTP/HTTPS"
            }
        },
        "service_list": {
            "response": "Services unavailable",
            "details": {
                "authentication": "JWT Token-based auth",
                "menu_system": "Interactive menu API",
                "question_answering": "Dynamic Q&A system",
                "network_access": "Multi-IP support"
            }
        },
        "service_status": {
            "response": "Services state",
            "details": {
                "auth_service": "running",
                "api_service": "running",
                "logging": "active",
                "monitoring": "active"
            }
        },
        "uptime": {
            "response": "Uptime details",
            "details": {
                "started": "2024-01-01",
                "uptime_percentage": "99.9%",
                "last_restart": "N/A",
                "current_session": "Active"
            }
        },
        "performance": {
            "response": "System performance",
            "details": {
                "response_time": "< 100ms",
                "concurrent_users": "Unlimited",
                "requests_per_second": "1000+",
                "cache_hit_rate": "95%"
            }
        },
        "how_to_use": {
            "response": "User guide",
            "details": {
                "step1": "1. Autenticate with POST /auth/login",
                "step2": "2. Use the Bearer token in the Authorization header",
                "step3": "3. GET /info for the full menu",
                "step4": "4. Ask questions with POST /ask or GET /question/{id}",
                "documentation": "Documentation"
            }
        },
        "api_documentation": {
            "response": "Documentation API FastAPI",
            "details": {
                "interactive_docs": "/docs (Swagger UI)",
                "alternative_docs": "/redoc (ReDoc)",
                "openapi_spec": "/openapi.json",
                "postman_collection": "Available on request"
            }
        },
        "contact_support": {
            "response": "Support technique",
            "details": {
                "email": "support@votre-domaine.com",
                "hours": "24/7",
                "response_time": "< 2h",
                "support_channels": ["Email", "API", "Documentation"]
            }
        },
        "faq": {
            "response": "Frequently Asked Questions",
            "details": {
                "q1": "How to get a token ? -> POST /auth/login",
                "q2": "Validity of this token ? -> 30 minutes",
                "q3": "How to renew it ? -> Reconnect",
                "q4": "Support HTTPS ? -> Required in production"
            }
        },
        "user_stats": {
            "response": " User statistics (Admin)",
            "details": {
                "total_users": len(USERS_DB),
                "active_sessions": 1,
                "admin_users": len([u for u in USERS_DB.values() if u["role"] == "admin"]),
                "regular_users": len([u for u in USERS_DB.values() if u["role"] == "user"])
            },
            "admin_only": True
        },
        "system_logs": {
            "response": "System logs (Admin)",
            "details": {
                "log_level": "INFO",
                "recent_activity": "Normal operations",
                "error_count": 0,
                "warning_count": 0
            },
            "admin_only": True
        },
        "config_info": {
            "response": "System configuration (Admin)",
            "details": {
                "token_expiry": f"{ACCESS_TOKEN_EXPIRE_MINUTES} minutes",
                "security": "JWT + bcrypt",
                "cors_enabled": True,
                "logging_enabled": True
            },
            "admin_only": True
        },
        "security_status": {
            "response": "Security state (Admin)",
            "details": {
                "authentication": "JWT Active",
                "password_hashing": "bcrypt",
                "cors_policy": "Configured",
                "https_recommended": True
            },
            "admin_only": True
        }
    }

# Tools functions
def get_server_ips():
    """Get server IP addresses"""
    try:
        hostname = socket.gethostname()
        ips = [socket.gethostbyname(hostname)]
        
        # Try to get all IPs (Linux/Unix)
        import subprocess
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        if result.returncode == 0:
            all_ips = result.stdout.strip().split()
            ips.extend([ip for ip in all_ips if ip not in ips])
        
        return ips
    except Exception:
        return ["127.0.0.1"]

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = USERS_DB.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalide",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"username": username, "role": payload.get("role")}
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Main routes

@app.get("/", tags=["Accueil"])
async def root(request: Request):
    """Welcome page with basic API info"""
    client_ip = request.client.host
    server_ips = get_server_ips()
    
    return {
        "message": "Welcome to the Interactive Menu API",
        "version": "1.0.0",
        "framework": "FastAPI",
        "connection_info": {
            "client_ip": client_ip,
            "server_ips": server_ips,
            "port": 8000
        },
        "quick_links": {
            "documentation": "/docs",
            "health_check": "/health",
            "login": "POST /auth/login",
            "menu": "GET /info (authentification required)"
        },
        "test_accounts": {
            "admin": "admin123 (full admin access)",
            "user": "user123 (user access)"
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Système"])
async def health_check(request: Request):
    """Health check of the API"""
    client_ip = request.client.host
    
    return {
        "status": "healthy",
        "message": "API is operational",
        "details": {
            "version": "1.0.0",
            "framework": "FastAPI",
            "database": "In-memory",
            "uptime": "99.9%"
        },
        "network": {
            "client_ip": client_ip,
            "server_ips": get_server_ips(),
            "accessible": True
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/network", tags=["Système"])
async def network_info(request: Request):
    """Full network connectivity info"""
    client_ip = request.client.host
    
    headers_info = {
        "host": request.headers.get("host"),
        "user-agent": request.headers.get("user-agent"),
        "x-forwarded-for": request.headers.get("x-forwarded-for"),
        "x-real-ip": request.headers.get("x-real-ip")
    }
    
    return {
        "connection_info": {
            "client_ip": client_ip,
            "server_ips": get_server_ips(),
            "port": 8000,
            "protocol": "HTTP"
        },
        "headers": {k: v for k, v in headers_info.items() if v},
        "test_endpoints": [
            f"http://{ip}:8000/health" for ip in get_server_ips()
        ],
        "timestamp": datetime.now().isoformat()
    }

# Authentication routes
@app.post("/auth/login", response_model=Token, tags=["Authentication"])
async def login(user_data: UserLogin, request: Request):
    """User login to get a JWT token"""
    client_ip = request.client.host
    user = authenticate_user(user_data.username, user_data.password)
    
    if not user:
        logger.warning(f"Connexion failed: {user_data.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username or password incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    
    logger.info(f"Connexion succeed: {user_data.username} depuis {client_ip}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# Menu and Questions routes
@app.get("/info", tags=["Menu"])
async def get_menu(current_user: dict = Depends(verify_token), request: Request = None):
    """Return the full API menu"""
    client_ip = request.client.host if request else "Unknown"
    logger.info(f"Menu read by: {current_user['username']} depuis {client_ip}")
    
    return {
        "message": "Full API Menu",
        "user_info": {
            "username": current_user["username"],
            "role": current_user["role"],
            "access_level": "Full" if current_user["role"] == "admin" else "Standard"
        },
        "menu": MENU_STRUCTURE,
        "server_info": {
            "ips": get_server_ips(),
            "port": 8000,
            "client_ip": client_ip
        },
        "usage_tip": "Use GET /menu/categories to list categories and POST /ask to ask questions",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/menu/categories", tags=["Menu"])
async def get_categories(current_user: dict = Depends(verify_token)):
    """List all available question categories"""
    categories = {}
    user_role = current_user["role"]
    
    for cat, info in MENU_STRUCTURE["categories"].items():
        if cat == MenuCategory.ADMIN and user_role != "admin":
            continue
        categories[cat.value] = info["description"]
    
    return {
        "categories": categories,
        "user_info": {
            "username": current_user["username"],
            "role": user_role,
            "admin_access": user_role == "admin"
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/questions/list", tags=["Questions"])
async def list_questions(current_user: dict = Depends(verify_token)):
    """List all available question categories and questions"""
    user_role = current_user["role"]
    filtered_questions = {}
    
    for category, info in MENU_STRUCTURE["categories"].items():
        if category == MenuCategory.ADMIN and user_role != "admin":
            continue
        filtered_questions[category.value] = info["questions"]
    
    total_questions = sum(len(q) for q in filtered_questions.values())
    
    return {
        "available_questions": filtered_questions,
        "statistics": {
            "total_questions": total_questions,
            "categories": len(filtered_questions),
            "user_access_level": user_role
        },
        "usage": "Use POST /ask or GET /question/{id} to ask a question",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/ask", tags=["Questions"])
async def ask_question(request_data: QuestionRequest, current_user: dict = Depends(verify_token), request: Request = None):
    """Answer a specific question based on its ID via POST"""
    return await process_question(request_data.question_id, current_user, request)

@app.get("/question/{question_id}", tags=["Questions"])
async def ask_question_get(question_id: str, current_user: dict = Depends(verify_token), request: Request = None):
    """Answer a specific question based on its ID via GET"""
    return await process_question(question_id, current_user, request)

async def process_question(question_id: str, current_user: dict, request: Request = None):
    """Question processing logic"""
    client_ip = request.client.host if request else "Unknown"
    question_responses = get_question_responses()
    
    if question_id not in question_responses:
        available_questions = list(question_responses.keys())
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"Question '{question_id}' non trouvée",
                "available_questions": available_questions,
                "categories": list(MENU_STRUCTURE["categories"].keys())
            }
        )
    
    question_data = question_responses[question_id]
    
    # Check admin-only questions
    if question_data.get("admin_only", False) and current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access denied",
                "message": "This question is restricted to admin users",
                "user_role": current_user["role"],
                "required_role": "admin"
            }
        )
    
    logger.info(f"❓ Question '{question_id}' asked by: {current_user['username']} from {client_ip}")
    
    return {
        "question_id": question_id,
        "asked_by": {
            "username": current_user["username"],
            "role": current_user["role"],
            "ip": client_ip
        },
        "response": question_data["response"],
        "details": question_data.get("details", {}),
        "metadata": {
            "category": next((cat.value for cat, info in MENU_STRUCTURE["categories"].items() 
                            if question_id in info["questions"]), "unknown"),
            "admin_only": question_data.get("admin_only", False)
        },
        "timestamp": datetime.now().isoformat()
    }

# Global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    client_ip = request.client.host
    logger.error(f"Error not handled by {client_ip}: {str(exc)}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "Error not handled",
            "support": "Contact support if the issue persists",
            "timestamp": datetime.now().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    server_ips = get_server_ips()
    
    print("🚀 API Menu FastAPI - Starting")
    print("=" * 50)
    print(f"📋 Title : API Menu Interactif FastAPI")
    print(f"🔗 Framework: FastAPI")
    print(f"🖥️ Servers IPs: {', '.join(server_ips)}")
    print(f"🔌 Port: 8000 (on all interfaces)")
    print(f"📖 Documentation: http://{server_ips[0]}:8000/docs")
    print(f"📚 ReDoc: http://{server_ips[0]}:8000/redoc")
    print("\n🌐 URLs access:")
    for ip in server_ips:
        print(f"   http://{ip}:8000")
    print("\n🔑 Test accounts:")
    print("   - admin/admin123 (full admin access)")
    print("   - user/user123 (user only access)")
    print("\n📋 Main endpoints:")
    print("   GET  / - Welcome page")
    print("   GET  /health - Health check")
    print("   POST /auth/login - Connexion")
    print("   GET  /info - Full menu (auth)")
    print("   POST /ask - Ask a question (auth)")
    print("   GET  /question/{id} - Direct question (auth)")
    print("\n💡 Quick test:")
    print(f"   curl http://{server_ips[0]}:8000/health")
    print("=" * 50)
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",  # Listen on all interfaces
            port=8000,
            log_level="info",
            access_log=True,
            reload=False  # Deactivated in production
        )
    except Exception as e:
        logger.error(f"Critical error on startup: {e}")
        exit(1)