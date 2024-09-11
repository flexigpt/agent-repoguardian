import json
import traceback
from typing import Dict, List, Optional

from ...llm.consts import ModelInfo
from ...llm.provider import askAI
from ...logging.logging import logger
from ..prompts import code_schema
from ..prompts import scan_schema
from ..prompts.templates import VULN_SCAN_CODE_V4_BLOCK_CLASSIFICATION_PROMPT
from ..prompts.templates import VULN_SCAN_CODE_V4_BLOCK_ISSUE_ANALYSIS_PROMPT
from .data_fetch import CWE_ALL_FUNCTIONAL_CATEGORIES
from .data_fetch import CWE_ALL_FUNCTIONAL_DETAILS


def initialize_scan_response_v4(scan_item: scan_schema.ScanItem,
                                scan_type: scan_schema.ScanType) -> scan_schema.VulnerabilityScanResponseV4:
    return scan_schema.VulnerabilityScanResponseV4.model_validate({"id": scan_item.id, "scan_type": scan_type})


def format_input_for_label_detection(lines: List[str]) -> str:
    structured_input = ""
    for i, line in enumerate(lines):
        structured_input += f"{i + 1}: {line}\n"
    return structured_input


def label_code_blocks(model_obj: ModelInfo, batch: List[code_schema.CodeItem],
                      prompt_template: str) -> tuple[Optional[scan_schema.CodeBlockListV4], Optional[List[str]]]:
    try:
        batch_size = sum(item.tokens for item in batch)
        if batch_size > model_obj.max_prompt_length:
            logger.warning("Batch size too large: %s", batch_size)
            return None, []
        all_lines = []
        for code_item in batch:
            lines = code_item.codestr.split('\n')
            for line in lines:
                if line.strip():
                    all_lines.append(line.strip())
        if not all_lines:
            logger.warning("No lines found")
            return None, []
        prompt_kwargs = {
            "functional_areas": str(CWE_ALL_FUNCTIONAL_CATEGORIES),
            "code": format_input_for_label_detection(all_lines),
        }
        # logger.debug("AI label request \n%s", prompt_kwargs)
        response = askAI(model_obj, prompt_template, scan_schema.CodeBlockListV4, prompt_kwargs)
        # if isinstance(response, BaseModel):
        #     logger.debug("AI label pydantic response \n%s", response.model_dump_json(indent=2, exclude_none=True))
        # else:
        #     logger.debug("AI label str response \n%s", response)

        return response, all_lines
    except Exception as e:
        logger.error("Error processing batch: %s. Size: %s", e, batch_size)
        return None, []


def get_unique_block_contexts(labeled_code_blocks: scan_schema.CodeBlockListV4, all_lines: List[str]) -> List[Dict]:
    unique_functional_area_blocks = {}
    # logger.info(CWE_ALL_FUNCTIONAL_DETAILS)
    for code_block in labeled_code_blocks.code_blocks:
        if not code_block.line_nos or not code_block.functional_areas:
            continue

        possible_issues = []
        for t in code_block.functional_areas:
            if (t.primary_area
                    not in CWE_ALL_FUNCTIONAL_DETAILS) or (t.secondary_area
                                                           not in CWE_ALL_FUNCTIONAL_DETAILS[t.primary_area]):
                continue
            if t.primary_area not in unique_functional_area_blocks:
                unique_functional_area_blocks[t.primary_area] = {}
            if t.secondary_area not in unique_functional_area_blocks[t.primary_area]:
                unique_functional_area_blocks[t.primary_area][t.secondary_area] = []
            # Append the line nos to each functional area. this may result in duplicates, but ok for now.
            unique_functional_area_blocks[t.primary_area][t.secondary_area].append(code_block.line_nos)

    all_blocks = []
    for primary_area, secondary_dict in unique_functional_area_blocks.items():
        for secondary_area, linenos_list in secondary_dict.items():
            block_context = {}
            if not linenos_list:
                continue
            block_context["Primary Functional Area"] = primary_area
            block_context["Sub Functional Area"] = secondary_area
            area_list = CWE_ALL_FUNCTIONAL_DETAILS[primary_area][secondary_area]
            possible_issues = []
            for cwe_info in area_list:
                possible_issues.append(cwe_info["Name"])
            if possible_issues:
                block_context["Example issues to look for"] = possible_issues

            block_context["Code lines"] = []
            for block_line_list in linenos_list:
                for line_no in block_line_list:
                    if 0 <= line_no < len(all_lines):
                        block_context["Code lines"].append(all_lines[line_no])
            if block_context["Code lines"]:
                all_blocks.append(block_context)
    return all_blocks


def deep_scan_on_labels(model_obj: ModelInfo, labeled_code_blocks: scan_schema.CodeBlockListV4, all_lines: List[str],
                        prompt_template: str) -> Optional[List[scan_schema.VulnerabilityBatchResponseV4]]:
    all_resps = []
    try:
        all_blocks = get_unique_block_contexts(labeled_code_blocks, all_lines)
        if not all_blocks:
            logger.debug("No blocks found. Skipping.")
            return None

        for block in all_blocks:
            try:
                block_str = json.dumps(block, indent=2)
                prompt_kwargs = {
                    "code_blocks": block_str,
                }
                response = askAI(model_obj, prompt_template, code_schema.VulnerabilityPromptResponseV2, prompt_kwargs)
                if not response:
                    logger.debug("No response recieved from AI")
                    continue

                all_resps.append(
                    scan_schema.VulnerabilityBatchResponseV4.model_validate({
                        "code_block": block,
                        "scan_response": response
                    }))
            except Exception as e:
                logger.error("Error during deep scan batch: %s", e)
        return all_resps
    except Exception as e:
        logger.error("Error during deep scan: %s", e)
        traceback.print_exc()
        return None


def process_batch(model_obj: ModelInfo,
                  batch: List[code_schema.CodeItem]) -> Optional[List[scan_schema.VulnerabilityBatchResponseV4]]:
    labeled_code_blocks, all_lines = label_code_blocks(model_obj, batch, VULN_SCAN_CODE_V4_BLOCK_CLASSIFICATION_PROMPT)
    if not labeled_code_blocks:
        logger.debug("No labels could be assigned. Skipping.")
        return None

    deep_scan_results = deep_scan_on_labels(model_obj, labeled_code_blocks, all_lines,
                                            VULN_SCAN_CODE_V4_BLOCK_ISSUE_ANALYSIS_PROMPT)
    if not deep_scan_results:
        logger.debug("No response recieved.")
        return None

    return deep_scan_results


def do_vuln_scan_v4(model_obj: ModelInfo, scan_item: scan_schema.ScanItem, scan_type: scan_schema.ScanType,
                    batches: List[List[code_schema.CodeItem]]) -> Optional[scan_schema.VulnerabilityScanResponseV4]:

    scan_response = initialize_scan_response_v4(scan_item, scan_type)
    for batch in batches:
        deep_scan_results = process_batch(model_obj, batch)
        if deep_scan_results:
            scan_response.scan_responses.extend(deep_scan_results)

    logger.debug("Total number of responses: %s\nAI Response full scan \n%s", len(scan_response.scan_responses),
                 scan_response.model_dump_json(indent=2, exclude_none=True))
    return scan_response
