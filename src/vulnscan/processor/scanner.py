from typing import Optional

from pydantic.v1 import BaseModel

from ...llm.consts import ModelInfo
from ...logging.logging import logger
from ..prompts import scan_schema
from ..prompts import scan_schema_utils
from .scanv1 import do_vuln_scan_v1
from .scanv2 import do_vuln_scan_v2
from .scanv3 import do_vuln_scan_v3
from .scanv4 import do_vuln_scan_v4
from .scanv5 import do_vuln_scan_v5


def do_vuln_scan(model_obj: ModelInfo, scan_item: scan_schema.ScanItem, scan_type: scan_schema.ScanType,
                 prompt_type: scan_schema.PromptType) -> Optional[BaseModel]:

    batches = scan_schema_utils.get_code_items_batches(model_obj, scan_item, scan_type)
    if not batches or not batches[0]:
        logger.warning("No code available for scan_item: %s", scan_item.id)
        return None
    if prompt_type == scan_schema.PromptType.SIMPLE:
        return do_vuln_scan_v1(model_obj, scan_item, scan_type, batches)
    if prompt_type == scan_schema.PromptType.SIMPLE_BATCHED:
        return do_vuln_scan_v2(model_obj, scan_item, scan_type, batches)
    if prompt_type == scan_schema.PromptType.SIMPLE_BATCHED_LABELED:
        return do_vuln_scan_v3(model_obj, scan_item, scan_type, batches)
    if prompt_type == scan_schema.PromptType.SIMPLE_BATCHED_CODE_CLASSIFIED:
        return do_vuln_scan_v4(model_obj, scan_item, scan_type, batches)
    if prompt_type == scan_schema.PromptType.LARGE_BATCH_CODE_CLASSIFIED:
        return do_vuln_scan_v5(model_obj, scan_item, scan_type, batches)
    return None
