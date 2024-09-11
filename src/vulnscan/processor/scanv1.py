from typing import List, Optional

from ...llm.consts import ModelInfo
from ...llm.provider import askAI
from ...logging.logging import logger
from ..prompts import code_schema
from ..prompts import scan_schema
from ..prompts.templates import VULN_SCAN_CODE_V1
from ..prompts.templates import VULN_SCAN_DIFF_V1


# Reusing the function to initialize the scan response
def initialize_scan_response_v1(scanitem: scan_schema.ScanItem,
                                scan_type: scan_schema.ScanType) -> scan_schema.VulnerabilityScanResponseV1:
    return scan_schema.VulnerabilityScanResponseV1.model_validate({"id": scanitem.id, "scan_type": scan_type})


def process_batch(model_obj: ModelInfo, batch: List[code_schema.CodeItem],
                  prompt_template: str) -> Optional[List[scan_schema.FileScanResponse]]:

    file_responses = []
    for item in batch:
        # Create the file response
        file_resp = scan_schema.FileScanResponse.model_validate({
            "filename": item.filename,
            "programming_language": item.programming_language,
        })

        prompt_kwargs = {
            "filename": item.filename,
            "programming_language": item.programming_language,
            "code": item.code
        }
        try:
            resp_obj = askAI(model_obj, prompt_template, scan_schema.VulnerabilityPromptResponse, prompt_kwargs)
            file_resp.llm_resp = resp_obj
            file_responses.append(file_resp)
        except Exception as e:
            logger.error("Got error for file: %s. Error: %s", item.filename, e)
    return file_responses


# Main function to perform the vulnerability scan (V1)
def do_vuln_scan_v1(model_obj: ModelInfo, scanitem: scan_schema.ScanItem, scan_type: scan_schema.ScanType,
                    batches: List[List[code_schema.CodeItem]]) -> Optional[scan_schema.VulnerabilityScanResponseV1]:

    scan_response = initialize_scan_response_v1(scanitem, scan_type)
    prompt_template = VULN_SCAN_CODE_V1
    if scan_type == scan_schema.ScanType.CODE_DIFF:
        prompt_template = VULN_SCAN_DIFF_V1
    for batch in batches:
        resp_obj = process_batch(model_obj, batch, prompt_template)
        if resp_obj:
            scan_response.scan_responses.extend(resp_obj)

    logger.debug("AI Response \n%s", scan_response.model_dump_json(indent=2, exclude_none=True))
    return scan_response
