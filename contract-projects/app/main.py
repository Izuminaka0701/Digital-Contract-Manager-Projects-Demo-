"""
Main FastAPI application
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
from contextlib import asynccontextmanager

from app.config import settings
# --- SỬA LỖI IMPORT ---
# 1. Import cái CLASS 'SupabaseClient' từ file của nó
from app.core.supabase_client import SupabaseClient 
# 2. Import cái MODULE (file) 'supabase_client.py' và đặt tên là 'supabase_module'
from app.core import supabase_client as supabase_module 
# --------------------
from app.api import auth, contracts, keys, users, audit

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events"""
    # Startup
    logger.info("Starting up Digital Contract Manager...")
    
    # Initialize Supabase client
    # Dòng này giờ sẽ gán instance 'SupabaseClient' vào biến toàn cục 'supabase_client'
    # bên trong file 'app/core/supabase_client.py' (mà ta đã import là 'supabase_module')
    supabase_module.supabase_client = SupabaseClient(
        settings.SUPABASE_URL,
        settings.SUPABASE_KEY
    )
    logger.info("Supabase client initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    # --- THÊM LOGIC SHUTDOWN ---
    # Rất quan trọng để "dọn dẹp"
    supabase_module.supabase_client = None
    logger.info("Supabase client shut down.")
    # ---------------------------


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Secure digital contract management with cryptographic signatures",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error_code": "INTERNAL_ERROR"
        }
    )


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Root endpoint
@app.get("/")
async def root(request: Request):
    """Serve landing page"""
    return templates.TemplateResponse("index.html", {"request": request})


# Dashboard
@app.get("/dashboard")
async def dashboard(request: Request):
    """Serve dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})


# Contracts page
@app.get("/contracts")
async def contracts_page(request: Request):
    """Serve contracts page"""
    return templates.TemplateResponse("contracts.html", {"request": request})


# Keys page
@app.get("/keys")
async def keys_page(request: Request):
    """Serve keys management page"""
    return templates.TemplateResponse("keys.html", {"request": request})


# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(contracts.router, prefix="/api/contracts", tags=["Contracts"])
app.include_router(keys.router, prefix="/api/keys", tags=["Signing Keys"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit Logs"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )