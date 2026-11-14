from .main import app
import uvicorn
from .config import settings
uvicorn.run(app, host=settings.host, port=settings.port)
