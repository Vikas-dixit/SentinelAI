from typing import Optional

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_type: str = Field(..., examples=["login"])
    source_ip: Optional[str] = None
    username: Optional[str] = None
    success: Optional[bool] = None
    failed_attempts: int = 0
    destination_port: Optional[int] = None
    process_name: Optional[str] = None
    bytes_sent: int = 0
    destination_ip: Optional[str] = None
