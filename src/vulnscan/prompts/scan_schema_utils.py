from typing import List

from . import code_schema
from . import scan_schema
from ...llm.consts import ModelInfo
from ...llm.tokens import get_tokens_from_string
from ...logging.logging import logger


def generate_item_string(item: code_schema.CodeItem) -> str:
    return (f"Filename: {item.filename}\n"
            f"Language: {item.programming_language}\n"
            f"Code:\n{item.code}\n\n")


def get_code_items(model_obj: ModelInfo, scan_type: scan_schema.ScanType,
                   change: scan_schema.DiffItem) -> List[code_schema.CodeItem]:

    # Determine the code to scan based on scan_type
    if scan_type == scan_schema.ScanType.CODE_AFTER:
        code_to_scan = change.code_after
    elif scan_type == scan_schema.ScanType.CODE_DIFF:
        code_to_scan = change.diff
    else:
        code_to_scan = change.code_before

    # Create a CodeItem instance
    item = code_schema.CodeItem(
        filename=change.filename,
        programming_language=change.programming_language,
        code=code_to_scan,
    )

    # Generate the item string
    item.codestr = generate_item_string(item)

    # Calculate the token count
    change_tokens = get_tokens_from_string(model_obj.name, model_obj.provider, item.codestr)

    # Check if the item exceeds the max prompt length
    if change_tokens > model_obj.max_prompt_length:
        logger.warning("Big file found. Skipping. Name: %s. Tokens in change: %s", item.filename, change_tokens)
        return []

    # Update the item with the token count
    item.tokens = change_tokens

    return [item]


# Function to collect code items from scan_item changes
def collect_code_items(model_obj: ModelInfo, scan_item: scan_schema.ScanItem,
                       scan_type: scan_schema.ScanType) -> List[code_schema.CodeItem]:
    code_items = []
    for change in scan_item.changes:
        items = get_code_items(model_obj, scan_type, change)
        code_items.extend(items)
    return code_items


# Function to log batch information
def log_batch_info(batches: List[List[code_schema.CodeItem]]):
    sizes = [item.tokens for batch in batches for item in batch]
    total_size = sum(sizes)
    logger.info("Got batches no: %s, Total size: %s. Batch sizes: %s", len(batches), total_size, sizes)


# Function to get code items batches based on max tokens
def get_code_items_batches_for_max_tokens(max_tokens: int,
                                          code_items: List[code_schema.CodeItem]) -> List[List[code_schema.CodeItem]]:
    batches = []
    batch_size = 0
    batch = []

    for item in code_items:
        t = item.tokens
        if batch_size + t > max_tokens:
            batches.append(batch)
            batch = []
            batch_size = 0  # Reset batch_size after appending the batch
        batch.append(item)
        batch_size += t

    if batch:  # Append the last batch if it's not empty
        batches.append(batch)

    # Step 4: Log batch information
    log_batch_info(batches)

    return batches


def get_code_items_batches(model_obj: ModelInfo, scan_item: scan_schema.ScanItem,
                           scan_type: scan_schema.ScanType) -> List[List[code_schema.CodeItem]]:
    code_items = collect_code_items(model_obj, scan_item, scan_type)

    if not code_items:
        logger.warning("No code available for scan_item: %s", scan_item.id)
        return []

    return get_code_items_batches_for_max_tokens(model_obj.max_prompt_length, code_items)
