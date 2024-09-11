from typing import List, Optional

from pydantic import BaseModel

from ...llm.consts import ModelInfo
from ...logging.logging import logger
from ...vulnscan.processor.scanner import do_vuln_scan
from ...vulnscan.prompts import scan_schema
from .evalitem import EvalItem


def process_eval(model: ModelInfo, eval_id: str, eval_obj: EvalItem, scan_type: scan_schema.ScanType,
                 prompt_type: scan_schema.PromptType) -> BaseModel:
    logger.info("Started processing: %s", eval_id)
    scanitem = evalitem_to_scanitem(eval_obj)
    if not scanitem:
        logger.warning("ID: %s. Nothing to scan", eval_id)
        return None
    result = do_vuln_scan(model, scanitem, scan_type, prompt_type)
    logger.info("Done scan ID: %s.", eval_id)
    return result


def evalitem_to_scanitem(eval_item: EvalItem) -> Optional[scan_schema.ScanItem]:
    diff_items: List[scan_schema.DiffItem] = []
    if not eval_item.changes:
        return None
    for change in eval_item.changes:
        diff_item = scan_schema.DiffItem(file_change_id=change.file_change_id,
                                         hash=change.hash,
                                         filename=change.filename,
                                         old_path=change.old_path,
                                         new_path=change.new_path,
                                         change_type=change.change_type,
                                         diff=change.diff,
                                         code_after=change.code_after,
                                         code_before=change.code_before,
                                         programming_language=change.programming_language)
        diff_items.append(diff_item)

    scan_item = scan_schema.ScanItem(id=eval_item.id,
                                     summary=eval_item.summary,
                                     details=eval_item.details,
                                     changes=diff_items)

    return scan_item
