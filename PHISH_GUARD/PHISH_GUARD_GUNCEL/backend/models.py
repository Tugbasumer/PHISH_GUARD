from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    email: str

class AnalysisRequest(BaseModel):
    text: str

class URLAnalysisRequest(BaseModel):
    url: str

from typing import List, Optional

class AnalysisResponse(BaseModel):
    input: str
    type: str
    score: int
    label: str
    reasons: List[str]
    notes: Optional[str] = "offline-analysis"
