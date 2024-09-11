from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel
from pydantic import Field

from .code_schema import FileScanResponse
from .code_schema import VulnerabilityPromptResponse
from .code_schema import VulnerabilityPromptResponseV2

# from pydantic.v1 import BaseModel
# from pydantic.v1 import Field


class PromptType(str, Enum):
    SIMPLE = "simple"
    SIMPLE_BATCHED = "batched"
    SIMPLE_BATCHED_LABELED = "labeled"
    SIMPLE_BATCHED_CODE_CLASSIFIED = "classified"
    LARGE_BATCH_CODE_CLASSIFIED = "largeclassified"


class ScanType(str, Enum):
    CODE_BEFORE = "before"
    CODE_AFTER = "after"
    CODE_DIFF = "diff"


class VulnerabilityScanResponseV1(BaseModel):
    id: str
    scan_type: ScanType
    scan_responses: Optional[List[FileScanResponse]] = []


class VulnerabilityScanResponseV2(BaseModel):
    id: str
    scan_type: ScanType
    scan_responses: Optional[List[VulnerabilityPromptResponse]] = []


class VulnerableLinesV3(BaseModel):
    """
    A list of line numbers in the code that are considered vulnerable.
    A list of labels that categorize the types of vulnerabilities found. E.g: XSS, SQLInjection, BufferOverflow, etc
    """
    line_nos: Optional[List[int]] = Field(default_factory=list)
    vulnerability_category_labels: Optional[List[str]] = Field(default_factory=list)


class VulnerabilityScanResponseV3(BaseModel):
    id: str
    scan_type: ScanType
    vulnerability_labels: List[VulnerableLinesV3] = []
    scan_responses: List[VulnerabilityPromptResponse] = []


class CodeBlockFunctionalAreasV4(BaseModel):
    """
    Primary and secondary functional areas that code block falls into
    """
    primary_area: str
    secondary_area: str


class CodeBlockV4(BaseModel):
    """
    A code block item that provides a array of line no integers and a tuple of primary and secondary functional areas.
    """
    line_nos: List[int] = Field(default_factory=list, description="A list of line numbers forming a code block.")
    functional_areas: List[CodeBlockFunctionalAreasV4] = Field(
        description='A list of functional areas that the code block lines fall into')


class CodeBlockListV4(BaseModel):
    """
    A list of labeled code blocks.
    """
    code_blocks: List[CodeBlockV4] = Field(default_factory=list, description="A list of labeled code blocks")


class VulnerabilityBatchResponseV4(BaseModel):
    code_block: Dict
    scan_response: VulnerabilityPromptResponseV2


class VulnerabilityScanResponseV4(BaseModel):
    id: str
    scan_type: ScanType
    scan_responses: List[VulnerabilityBatchResponseV4] = []


class DiffItem(BaseModel):
    file_change_id: str = Field(..., min_length=1)
    hash: str = Field(..., min_length=1)
    filename: str = Field(..., min_length=1)
    old_path: Optional[str] = Field(None, min_length=1)
    new_path: Optional[str] = Field(None, min_length=1)
    change_type: Optional[str] = Field(None, min_length=1)
    diff: Optional[str] = None
    code_after: Optional[str] = None
    code_before: Optional[str] = None
    programming_language: Optional[str] = Field(None, min_length=1)


class ScanItem(BaseModel):
    id: str
    summary: Optional[str] = None
    details: Optional[str] = None
    changes: Optional[List[DiffItem]] = None
