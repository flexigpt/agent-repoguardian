from typing import List, Optional

from pydantic.v1 import BaseModel

from ...llm.consts import ModelInfo
from ...llm.provider import askAI
from ...logging.logging import logger
from ..prompts import code_schema
from ..prompts import scan_schema
from ..prompts.templates import VULN_SCAN_CODE_V3
from ..prompts.templates import VULN_SCAN_CODE_V3_LABEL_DETECTION_PROMPT


def initialize_scan_response_v3(scan_item: scan_schema.ScanItem,
                                scan_type: scan_schema.ScanType) -> scan_schema.VulnerabilityScanResponseV3:
    return scan_schema.VulnerabilityScanResponseV3.model_validate({"id": scan_item.id, "scan_type": scan_type})


def format_input_for_label_detection(lines: List[str]) -> str:
    structured_input = ""
    for i, line in enumerate(lines):
        structured_input += f"{i + 1}: {line}\n"
    return structured_input


def identify_vuln_labels(model_obj: ModelInfo, batch: List[code_schema.CodeItem],
                         prompt_template: str) -> tuple[Optional[scan_schema.VulnerableLinesV3], Optional[List[str]]]:
    try:
        batch_size = sum(item.tokens for item in batch)
        if batch_size > model_obj.max_prompt_length:
            logger.warning("Batch size too large: %s", batch_size)
            return None, []

        all_lines = []
        for code_item in batch:
            lines = code_item.codestr.split('\n')
            all_lines.extend(lines)
        if not all_lines:
            logger.warning("No lines found")
            return None, []
        prompt_kwargs = {"code": format_input_for_label_detection(all_lines)}
        response = askAI(model_obj, prompt_template, scan_schema.VulnerableLinesV3, prompt_kwargs)
        if isinstance(response, BaseModel):
            logger.debug("AI label pydantic response \n%s", response.model_dump_json(indent=2, exclude_none=True))
        else:
            logger.debug("AI label str response \n%s", response)

        return response, all_lines
    except Exception as e:
        logger.error("Error processing batch: %s. Size: %s", e, batch_size)
        return None, []


def deep_scan_on_labels(model_obj: ModelInfo, labels: scan_schema.VulnerableLinesV3, all_lines: List[str],
                        prompt_template: str) -> Optional[code_schema.VulnerabilityPromptResponse]:
    try:
        vuln_code_lines = []
        for line_no in labels.line_nos:
            # Get the line number from the label (1-based index) and adjust it for 0-based index
            line_number = line_no - 1

            # Extract context: 2 lines before and 2 lines after the labeled line
            context_start = max(0, line_number - 2)
            context_end = min(len(all_lines), line_number + 3)
            line_context = "\n".join(all_lines[context_start:context_end])

            # Format the vulnerable code block with the label and its context
            vuln_code_lines.append(line_context)

        if not vuln_code_lines:
            return None
        # Prepare the prompt with the vulnerable code blocks for deep scan
        prompt_kwargs = {
            "linenos": ", ".join(str(lno) for lno in labels.line_nos),
            "labels": ", ".join(labels.vulnerability_category_labels),
            "code": "\n\n".join(vuln_code_lines),
        }
        response = askAI(model_obj, prompt_template, code_schema.VulnerabilityPromptResponse, prompt_kwargs)

        return response
    except Exception as e:
        logger.error("Error during deep scan: %s", e)
        return None


def process_batch(
    model_obj: ModelInfo, batch: List[code_schema.CodeItem]
) -> tuple[Optional[scan_schema.VulnerableLinesV3], Optional[scan_schema.VulnerabilityPromptResponse]]:
    vuln_labels, all_lines = identify_vuln_labels(model_obj, batch, VULN_SCAN_CODE_V3_LABEL_DETECTION_PROMPT)
    if not vuln_labels:
        logger.debug("No labels could be found. Skipping.")
        return (None, None)

    deep_scan_results = deep_scan_on_labels(model_obj, vuln_labels, all_lines, VULN_SCAN_CODE_V3)
    if not deep_scan_results:
        logger.debug("No labels could be found. Skipping.")
        return (None, None)

    logger.debug("Batch processing: AI Response scan \n%s",
                 deep_scan_results.model_dump_json(indent=2, exclude_none=True))
    return (vuln_labels, deep_scan_results)


def do_vuln_scan_v3(model_obj: ModelInfo, scan_item: scan_schema.ScanItem, scan_type: scan_schema.ScanType,
                    batches: List[List[code_schema.CodeItem]]) -> Optional[scan_schema.VulnerabilityScanResponseV3]:

    scan_response = initialize_scan_response_v3(scan_item, scan_type)
    for batch in batches:
        vuln_labels, deep_scan_results = process_batch(model_obj, batch)
        if vuln_labels and deep_scan_results:
            scan_response.vulnerability_labels.append(vuln_labels)
            scan_response.scan_responses.append(deep_scan_results)

    logger.debug("AI Response full scan \n%s", scan_response.model_dump_json(indent=2, exclude_none=True))
    return scan_response
