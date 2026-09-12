from fastapi import APIRouter

from api.content import router as content_router
from api.health import router as health_router
from api.events import router as events_router
from api.mcp import router as mcp_router
from api.output import router as output_router
from api.runtime import router as runtime_router
from api.prompt import router as prompt_router
from api.tool import router as tool_router

router = APIRouter(prefix="/v1")
router.include_router(health_router, tags=["health"])
router.include_router(events_router)
router.include_router(prompt_router)
router.include_router(content_router)
router.include_router(tool_router)
router.include_router(mcp_router)
router.include_router(output_router)
router.include_router(runtime_router)

