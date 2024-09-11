from typing import List, Optional

from go_vulnfixes_db.schemas.fixes import FileChange
from go_vulnfixes_db.schemas.osv import CweDetailsModel
from go_vulnfixes_db.schemas.osv import SeverityItem
from pydantic import BaseModel


class EvalItem(BaseModel):
    id: str
    aliases: Optional[List[str]] = None
    related: Optional[List[str]] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[List[SeverityItem]] = None
    cwe_details: Optional[List[CweDetailsModel]] = None
    changes: List[FileChange]


class EvalConfig(BaseModel):
    log_level: str

    cve_info_unified_path: str
    input_json_path: str
    outdata_path: str
    cwe_json_path: str

    openai_api_key: str
    anthropic_api_key: str

    use_models: List[str]
    use_prompt_types: List[str]
    use_scan_types: List[str]
