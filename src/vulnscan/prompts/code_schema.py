from typing import Optional

# from pydantic.v1 import BaseModel
from pydantic import BaseModel


class CodeItem(BaseModel):
    filename: str
    programming_language: str
    code: str
    codestr: str = ""
    tokens: int = 0


class VulnerabilityPromptResponse(BaseModel):
    """
    vuln: A boolean to indicate if a vulnerability exists or not, 
    description: A string containing analysis
    """
    vuln: bool
    description: str = ""


class VulnerabilityPromptResponseV2(BaseModel):
    """
    vuln_score: A int indicating vulnerability score between 0 to 10, 
    exploitable_vuln: A boolean to indicate if the vulnerability is exploitable or not, 
    description: A string containing analysis
    """
    vuln_score: int
    exploitable_vuln: bool
    description: str


class FileScanResponse(BaseModel):
    filename: str
    programming_language: str
    llm_resp: Optional[VulnerabilityPromptResponse] = None
