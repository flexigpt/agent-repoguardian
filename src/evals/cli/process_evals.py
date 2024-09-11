import argparse
import json
import os
import traceback
from typing import Dict

from dotenv import load_dotenv
from go_vulnfixes_db.fileutils.filehandle import write_json

from ...llm.consts import MODEL_INFO
from ...llm.consts import ModelInfo
from ...llm.tokens import TokenCounterManager
from ...logging.logging import configure_logging
from ...logging.logging import logger
from ..evalchange.evalitem import EvalConfig
from ..evalchange.evalitem import EvalItem
from ..evalchange.evaluate import process_eval
from ..evalchange.schema_utils import build_eval_data

# MAX_PROCESS_ITEMS = 1
MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10


def get_model_obj(eval_config: EvalConfig, model_name: str) -> ModelInfo:
    if model_name not in MODEL_INFO:
        raise ValueError(f"Model not found {model_name}")
    model_obj = MODEL_INFO[model_name]
    api_key_property_str = model_obj.provider.lower() + "_api_key"
    model_obj.api_key = eval_config.__getattribute__(api_key_property_str)
    if not model_obj.api_key:
        raise ValueError(f"APIKey not found {model_name}")
    return model_obj


def process_all_evals(eval_config: EvalConfig, eval_index: Dict[str, EvalItem], model_name: str, scan_type: str,
                      prompt_type: str):
    error_eval_ids = []
    all_results = []
    processed = 0
    counter = TokenCounterManager()
    model = get_model_obj(eval_config, model_name)
    counter.set_token_counter(model.name, model.provider)
    for eval_id, eval_obj in eval_index.items():
        try:
            result = process_eval(model, eval_id, eval_obj, scan_type, prompt_type)
            if result:
                all_results.append(result)
        except Exception as e:
            logger.error("An exception occured: %s", e)
            traceback.print_exc()
            error_eval_ids.append(eval_id)
            if len(error_eval_ids) >= MAX_ERRORS:
                break

        processed += 1
        if processed >= MAX_PROCESS_ITEMS:
            break

    base_input_name = os.path.splitext(os.path.basename(eval_config.input_json_path))[0]
    output_name = base_input_name + "_" + model_name + "_" + prompt_type + "_" + scan_type + "_results.json"
    if all_results:
        out_fpath = os.path.join(eval_config.outdata_path, output_name)
        results_dict_arr = [r.model_dump(exclude_none=True) for r in all_results]
        # results_dict_arr = [r.dict(exclude_none=True) for r in all_results]
        write_json(out_fpath, results_dict_arr)

    logger.info("Processed evals count: %s", processed)
    logger.info("Errored cves:\n%s", json.dumps(error_eval_ids, indent=2))
    logger.info("Tokens: %s", counter.get_counts())
    counter.reset_counts()


def main() -> None:
    eval_config = {}

    eval_config["log_level"] = os.getenv("LOG_LEVEL", "info")

    eval_config["cve_info_unified_path"] = os.path.abspath(os.path.expanduser(os.getenv("CVE_INFO_UNIFIED_PATH")))
    eval_config["input_json_path"] = os.path.abspath(os.path.expanduser(os.getenv("INPUT_JSON_PATH")))
    eval_config["outdata_path"] = os.path.abspath(os.path.expanduser(os.getenv("OUTDATA_PATH")))
    eval_config["cwe_json_path"] = os.path.abspath(os.path.expanduser(os.getenv("CWE_JSON_PATH")))

    eval_config["openai_api_key"] = os.getenv("OPENAI_API_KEY", "")
    eval_config["anthropic_api_key"] = os.getenv("ANTHROPIC_API_KEY", "")

    eval_config["use_models"] = os.getenv("USE_MODELS").lower().split(",")
    eval_config["use_prompt_types"] = os.getenv("USE_PROMPT_TYPES").lower().split(",")
    eval_config["use_scan_types"] = os.getenv("USE_SCAN_TYPES").lower().split(",")

    eval_config_obj = EvalConfig.model_validate(eval_config)
    logger.info("CVE_INFO_UNIFIED_PATH: %s, INPUT_JSON_PATH: %s", eval_config_obj.cve_info_unified_path,
                eval_config_obj.input_json_path)

    eval_index = build_eval_data(eval_config_obj.cve_info_unified_path, eval_config_obj.input_json_path)
    for model_name in eval_config_obj.use_models:
        for prompt_type in eval_config_obj.use_prompt_types:
            for scan_type in eval_config_obj.use_scan_types:
                process_all_evals(eval_config_obj, eval_index, model_name, scan_type, prompt_type)


def load_env():
    parser = argparse.ArgumentParser(description='Process some environment variables.')
    parser.add_argument('--env', type=str, help='The path to the .env file', required=True)

    # Parse the arguments
    args = parser.parse_args()

    # Load the .env file
    env_path = os.path.abspath(os.path.expanduser(args.env))
    if not os.path.exists(env_path):
        raise FileNotFoundError(f"The .env file at path '{env_path}' does not exist.")
    load_dotenv(env_path)
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    logger.info("Log level %s", log_level)
    configure_logging(level_str=log_level)
    logger.info("Loaded env from :%s", env_path)


if __name__ == "__main__":
    # python -m src.evals.cli.process_evals --env ./.env > out/out.txt 2>&1
    load_env()
    main()
