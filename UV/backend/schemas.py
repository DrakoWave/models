# schemas.py
"""
Pydantic Request and Response Schemas for UV- Ultra Vigilance.
Matches the exact schema expected by UltraVigilance Android App & Chrome Extension.
"""
from typing import List, Optional
from pydantic import BaseModel, Field

# Unified Response Model
class ScanVerdictResponse(BaseModel):
    verdict: str = Field(..., description="'FRAUD' | 'SUSPICIOUS' | 'SAFE' | 'UNKNOWN' (exact uppercase)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Risk level float from 0.0 to 1.0")
    reasons: List[str] = Field(default_factory=list, description="List of explanatory bullet strings")
    detail: Optional[str] = Field(default=None, description="Summary description string")

# Alias for backwards compatibility with previous internal references
VerdictResponse = ScanVerdictResponse

# Request Models
class ScanDocumentRequest(BaseModel):
    url: str = Field(..., description="Target document or domain URL to inspect")

class URLRequest(ScanDocumentRequest):
    pass

class ScanSmsRequest(BaseModel):
    sender: str = Field(default="", description="Sender header or phone number")
    message: Optional[str] = Field(default=None, description="SMS message body")
    text: Optional[str] = Field(default=None, description="Alternative field for SMS text")

    def get_text(self) -> str:
        return self.message if self.message is not None else (self.text or "")

class SMSRequest(ScanSmsRequest):
    pass

class PaymentRequest(BaseModel):
    upi_id: str = Field(default="", description="Target UPI VPA identifier")
    gateway_url: str = Field(default="", description="Payment checkout or gateway URL")
