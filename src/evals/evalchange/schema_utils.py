import os
import traceback
from typing import Dict, List, Optional

from go_vulnfixes_db.fileutils import filehandle
from go_vulnfixes_db.schemas import fixes
from go_vulnfixes_db.schemas import osv

from ...logging.logging import logger
# from ...logging.logging import logger
from .evalitem import EvalItem


def get_changes_to_process(fixes_data: Dict[str, any]) -> List[fixes.FileChange]:
    fixes_object = fixes.CVEFixes.model_validate(fixes_data)
    changes = []
    for change in fixes_object.changes:
        # Exclude Non go files
        if not change.filename.endswith(".go"):
            continue
        # Exclude test files
        if change.filename.endswith("test.go"):
            continue
        changes.append(change)
    return changes


def get_eval_object(cve_info_unified_path: str, cveinfo_rel_path: str, fixes_rel_path: str) -> Optional[EvalItem]:
    try:
        cveinfo_path = os.path.join(cve_info_unified_path, cveinfo_rel_path)
        fixes_path = os.path.join(cve_info_unified_path, fixes_rel_path)
        if not os.path.exists(cveinfo_path):
            logger.warning("CVE Info path doesn't exist: %s", cveinfo_path)
            return None
        if not os.path.exists(fixes_path):
            logger.warning("Fixes path doesn't exist: %s", fixes_path)
            return None

        cveinfo_data = filehandle.read_json(cveinfo_path)
        fixes_data = filehandle.read_json_zip(fixes_path)
        cveinfo_object = osv.OpenSourceVulnerability.model_validate(cveinfo_data)
        fix_changes = get_changes_to_process(fixes_data)
        if not fix_changes:
            logger.warning("No fixes to process: %s", cveinfo_rel_path)
            return None
        cwe_details = None
        if cveinfo_object.database_specific:
            cwe_details = cveinfo_object.database_specific.cwe_details
        eval_obj = EvalItem(id=cveinfo_object.id,
                            aliases=cveinfo_object.aliases,
                            related=cveinfo_object.related,
                            summary=cveinfo_object.summary,
                            details=cveinfo_object.details,
                            severity=cveinfo_object.severity,
                            cwe_details=cwe_details,
                            changes=fix_changes)

        return eval_obj
    except Exception as e:
        logger.error("Got error while processing: %s, %s", cveinfo_rel_path, e)
        traceback.print_exc()
        return None


def build_eval_data(cve_info_unified_path: str, input_json_path: str) -> Dict[str, EvalItem]:

    data = filehandle.read_json(input_json_path)

    eval_index = {}

    for entry_key, entry_value in data.items():
        if entry_key in eval_index:
            continue
        if entry_value and 'cveinfo' in entry_value and 'fixes' in entry_value:
            eval_obj = get_eval_object(cve_info_unified_path, entry_value["cveinfo"], entry_value["fixes"])
            if eval_obj:
                eval_index[entry_key] = eval_obj
    return eval_index
