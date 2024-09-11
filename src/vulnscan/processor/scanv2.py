from typing import List, Optional

from ...llm.consts import ModelInfo
from ...llm.provider import askAI
from ...logging.logging import logger
from ..prompts import code_schema
from ..prompts import scan_schema
from ..prompts.templates import VULN_SCAN_CODE_V2


# Function to validate and initialize the scan response
def initialize_scan_response(scan_item: scan_schema.ScanItem,
                             scan_type: scan_schema.ScanType) -> scan_schema.VulnerabilityScanResponseV2:
    return scan_schema.VulnerabilityScanResponseV2.model_validate({"id": scan_item.id, "scan_type": scan_type})


# Function to process a single batch of code items
def process_batch(model_obj: ModelInfo, batch: List[code_schema.CodeItem],
                  prompt_template: str) -> Optional[code_schema.VulnerabilityPromptResponse]:
    try:
        batch_size = sum(item.tokens for item in batch)
        if batch_size > model_obj.max_prompt_length:
            logger.warning("Found a big batch item. Size: %s", batch_size)
            return None

        # Construct the prompt using the code strings from the batch
        prompt_kwargs = {"code": "\n".join(item.codestr for item in batch)}
        resp_obj = askAI(model_obj, prompt_template, code_schema.VulnerabilityPromptResponse, prompt_kwargs)

        return resp_obj
    except Exception as e:
        logger.error("Got error for batch: %s. size:%s", e, batch_size)
        return None


# Main function to perform the vulnerability scan
def do_vuln_scan_v2(model_obj: ModelInfo, scan_item: scan_schema.ScanItem, scan_type: scan_schema.ScanType,
                    batches: List[List[code_schema.CodeItem]]) -> Optional[scan_schema.VulnerabilityScanResponseV2]:
    scan_response = initialize_scan_response(scan_item, scan_type)
    for batch in batches:
        resp_obj = process_batch(model_obj, batch, VULN_SCAN_CODE_V2)
        if resp_obj:
            scan_response.scan_responses.append(resp_obj)

    logger.debug("AI Response \n%s", scan_response.model_dump_json(indent=2, exclude_none=True))
    return scan_response
