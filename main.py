import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from pydantic import BaseModel, Field, BaseSettings, SecretStr
from cryptography.fernet import Fernet, InvalidToken

# --- Configuration ---

class Settings(BaseSettings):
    """Loads configuration from environment variables."""
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "secrets_db"
    POSTGRES_USER: str = "user"
    POSTGRES_PASSWORD: SecretStr = SecretStr("password")
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    # IMPORTANT: Generate a strong key using Fernet.generate_key() and store it securely
    # For example: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Store this key in an environment variable or secrets manager, NOT hardcoded.
    ENCRYPTION_KEY: SecretStr = SecretStr("_YqOr9f-e1OrJzZg_QDzsiKIJtW93d5zO5iMS8Hk8Vg=") # Example key, replace!
    DEFAULT_TTL_SECONDS: int = 3600 * 24 * 7 # Default 1 week TTL if not specified
    MIN_CACHE_TTL_SECONDS: int = 300 # Minimum 5 minutes cache TTL as required

    class Config:
        env_file = '.env' # Allow loading from a .env file for local dev
        env_file_encoding = 'utf-8'

settings = Settings()

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Global Variables (Connections) ---
# These will be initialized during FastAPI startup
db_pool: Optional[asyncpg.Pool] = None
redis_pool: Optional[aioredis.Redis] = None
fernet: Optional[Fernet] = None

# --- Database Interaction ---

async def init_db_pool():
    """Initializes the PostgreSQL connection pool."""
    global db_pool
    dsn = f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD.get_secret_value()}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    try:
        db_pool = await asyncpg.create_pool(dsn)
        # Create logs table if it doesn't exist
        async with db_pool.acquire() as connection:
            await connection.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    secret_key VARCHAR(36) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    ttl_seconds INTEGER NULL,
                    details TEXT NULL
                );
            """)
        logger.info("Database pool created and table checked/created.")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        # Depending on requirements, you might want to exit or retry
        raise

async def close_db_pool():
    """Closes the PostgreSQL connection pool."""
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database pool closed.")

async def log_action(secret_key: str, action: str, ip_address: Optional[str], ttl_seconds: Optional[int] = None, details: Optional[str] = None):
    """Logs an action to the PostgreSQL database."""
    if not db_pool:
        logger.error("Database pool not initialized, cannot log action.")
        return
    try:
        async with db_pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO logs (secret_key, action, ip_address, ttl_seconds, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                secret_key, action, ip_address, ttl_seconds, details
            )
    except Exception as e:
        logger.error(f"Failed to log action '{action}' for key '{secret_key}': {e}")

# --- Cache Interaction ---

async def init_redis_pool():
    """Initializes the Redis connection pool."""
    global redis_pool
    try:
        redis_pool = aioredis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, decode_responses=True)
        await redis_pool.ping()
        logger.info("Redis connection pool created.")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise # Or handle appropriately

async def close_redis_pool():
    """Closes the Redis connection pool."""
    global redis_pool
    if redis_pool:
        await redis_pool.close()
        logger.info("Redis connection pool closed.")

# --- Encryption ---

def init_encryption():
    """Initializes the Fernet cipher suite."""
    global fernet
    try:
        key = settings.ENCRYPTION_KEY.get_secret_value().encode()
        if not key:
            raise ValueError("ENCRYPTION_KEY environment variable not set.")
        fernet = Fernet(key)
        logger.info("Encryption service initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize encryption: {e}. Ensure ENCRYPTION_KEY is a valid Fernet key.")
        raise

def encrypt_data(data: str) -> str:
    """Encrypts string data."""
    if not fernet:
        raise RuntimeError("Encryption service not initialized.")
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> Optional[str]:
    """Decrypts string data. Returns None if decryption fails."""
    if not fernet:
        raise RuntimeError("Encryption service not initialized.")
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except InvalidToken:
        logger.warning("Invalid token encountered during decryption.")
        return None
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

# --- Pydantic Models ---

class SecretCreate(BaseModel):
    secret: str = Field(..., description="The confidential data to store.")
    passphrase: Optional[str] = Field(None, description="Optional passphrase (currently unused for deletion, but stored for future use).")
    ttl_seconds: Optional[int] = Field(None, description=f"Time-to-live in seconds. Defaults to {settings.DEFAULT_TTL_SECONDS} if not provided.")

class SecretCreateResponse(BaseModel):
    secret_key: str = Field(..., description="The unique key to retrieve the secret.")

class SecretGetResponse(BaseModel):
    secret: str = Field(..., description="The retrieved confidential data.")

class SecretDeleteResponse(BaseModel):
    status: str = Field("secret_deleted", description="Status confirming deletion.")

# --- FastAPI Application ---

app = FastAPI(
    title="Disposable Secrets Service",
    description="Store secrets that can be retrieved only once.",
    version="1.0.0"
)

# --- Dependency Injection ---

async def get_redis() -> aioredis.Redis:
    if not redis_pool:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis service not available")
    return redis_pool

# --- Event Handlers (Startup/Shutdown) ---

@app.on_event("startup")
async def startup_event():
    """Initialize resources on application startup."""
    init_encryption() # Initialize encryption first
    await init_redis_pool()
    await init_db_pool()

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on application shutdown."""
    await close_redis_pool()
    await close_db_pool()


# --- Helper Functions ---

def get_client_ip(request: Request) -> Optional[str]:
    """Extracts client IP address from request headers."""
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        # Take the first IP if there's a list (common proxy setup)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.client.host if request.client else None
    return ip

def set_no_cache_headers(response: Response):
    """Sets headers to prevent client and proxy caching."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

# --- API Endpoints ---

@app.post("/secret",
          response_model=SecretCreateResponse,
          status_code=status.HTTP_201_CREATED,
          summary="Create a new disposable secret")
async def create_secret(
    secret_data: SecretCreate,
    request: Request,
    redis: aioredis.Redis = Depends(get_redis)
):
    """
    Stores a new secret. The secret is encrypted and stored in the cache (Redis)
    with a specific Time-To-Live (TTL). A unique key is returned to retrieve it.
    """
    if not secret_data.secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Secret content cannot be empty.")

    secret_key = str(uuid.uuid4())
    encrypted_secret = encrypt_data(secret_data.secret)

    # Store passphrase if provided (could be hashed in a real app)
    # For this minimal version, we just store it alongside
    data_to_store: Dict[str, Any] = {"secret": encrypted_secret}
    if secret_data.passphrase:
        data_to_store["passphrase"] = secret_data.passphrase # Consider hashing this

    # Determine TTL, ensuring it meets the minimum cache requirement
    ttl = secret_data.ttl_seconds if secret_data.ttl_seconds is not None else settings.DEFAULT_TTL_SECONDS
    # Ensure TTL is positive and meets minimum cache requirement if specified > 0
    if ttl <= 0:
        ttl = settings.DEFAULT_TTL_SECONDS # Fallback to default if invalid TTL provided
    effective_ttl = max(ttl, settings.MIN_CACHE_TTL_SECONDS)

    try:
        # Store in Redis with TTL
        await redis.hset(secret_key, mapping=data_to_store)
        await redis.expire(secret_key, effective_ttl)

        # Log creation to PostgreSQL
        client_ip = get_client_ip(request)
        await log_action(
            secret_key=secret_key,
            action="create",
            ip_address=client_ip,
            ttl_seconds=effective_ttl,
            details=f"Passphrase provided: {'yes' if secret_data.passphrase else 'no'}"
        )

        return SecretCreateResponse(secret_key=secret_key)

    except Exception as e:
        logger.error(f"Error creating secret {secret_key}: {e}")
        # Attempt to clean up if partially created (optional)
        await redis.delete(secret_key)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create secret")


@app.get("/secret/{secret_key}",
         response_model=SecretGetResponse,
         summary="Retrieve a secret (only once)")
async def get_secret(
    secret_key: str,
    request: Request,
    response: Response,
    redis: aioredis.Redis = Depends(get_redis)
):
    """
    Retrieves the secret associated with the given key.
    This operation is destructive: the secret is deleted immediately after retrieval.
    Returns 404 if the secret is not found (already retrieved, expired, or never existed).
    """
    set_no_cache_headers(response) # Prevent caching of the response

    try:
        # Atomically get and delete using a Lua script or transaction (more robust)
        # Simple approach: Get, then Delete immediately. Small race condition window exists.
        # For higher guarantees, use Redis transactions (MULTI/EXEC) or Lua scripting.

        stored_data = await redis.hgetall(secret_key)

        if not stored_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found or already retrieved/expired.")

        # Immediately attempt to delete the key to ensure one-time retrieval
        deleted_count = await redis.delete(secret_key)

        if deleted_count == 0:
             # This means the key expired or was deleted between the hgetall and delete calls (race condition)
             logger.warning(f"Secret key {secret_key} disappeared before explicit deletion after retrieval attempt.")
             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret expired or was retrieved concurrently.")

        encrypted_secret = stored_data.get("secret")
        if not encrypted_secret:
             # Should not happen if hgetall succeeded, but good to check
             logger.error(f"Inconsistent state: Secret key {secret_key} found but 'secret' field missing.")
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal data inconsistency.")

        decrypted_secret = decrypt_data(encrypted_secret)

        if decrypted_secret is None:
            # Log issue but don't expose details
            logger.error(f"Failed to decrypt secret for key {secret_key}. Potential key mismatch or data corruption.")
            # Log the retrieval attempt even if decryption failed, as the key was consumed
            client_ip = get_client_ip(request)
            await log_action(secret_key=secret_key, action="retrieve_failed_decryption", ip_address=client_ip)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process secret.")

        # Log successful retrieval to PostgreSQL
        client_ip = get_client_ip(request)
        await log_action(secret_key=secret_key, action="retrieve", ip_address=client_ip)

        return SecretGetResponse(secret=decrypted_secret)

    except HTTPException as http_exc:
        # Re-raise HTTP exceptions directly
        raise http_exc
    except Exception as e:
        logger.error(f"Error retrieving secret {secret_key}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve secret")

@app.delete("/secret/{secret_key}",
            response_model=SecretDeleteResponse,
            summary="Delete a secret manually")
async def delete_secret(
    secret_key: str,
    request: Request,
    redis: aioredis.Redis = Depends(get_redis)
):
    """
    Manually deletes a secret before it's retrieved or expires.
    Currently does not require a passphrase (as per minimal requirements).
    Returns 404 if the secret doesn't exist.
    """
    # Note: Passphrase check omitted for minimal viable product.
    # In a full implementation, you'd retrieve the stored passphrase (if any)
    # compare it (ideally hashed) with a passphrase provided in the request body/header,
    # and only delete if they match.

    try:
        # Attempt to delete the key
        deleted_count = await redis.delete(secret_key)

        if deleted_count == 0:
            # Key didn't exist (already retrieved, expired, or never created)
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found.")

        # Log deletion to PostgreSQL
        client_ip = get_client_ip(request)
        await log_action(secret_key=secret_key, action="delete", ip_address=client_ip)

        return SecretDeleteResponse()

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Error deleting secret {secret_key}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete secret")

# --- Root endpoint (optional, for health check/info) ---
@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Disposable Secrets Service is running."}

# --- Uvicorn runner (for local development without Docker) ---
# if __name__ == "__main__":
#     import uvicorn
#     # Generate a key for local testing if needed:
#     # print(Fernet.generate_key().decode())
#     # Ensure .env file exists or env vars are set
#     uvicorn.run(app, host="0.0.0.0", port=8000)
