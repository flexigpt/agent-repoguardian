import json
from typing import Any, Dict

from llama_index.core.program import FunctionCallingProgram
from llama_index.llms.anthropic import Anthropic
from llama_index.llms.openai import OpenAI
from llama_index.program.openai import OpenAIPydanticProgram
from openai import OpenAI as baseOpenAI

from ..logging.logging import logger
from .consts import ModelInfo


def askOpenAIBase(model: ModelInfo, prompt_template: str, output_pydantic_cls: Any, prompt_kwargs: Dict[str,
                                                                                                        Any]) -> Any:
    if model.api_key == "":
        raise AttributeError("No API key set for model")

    llm = baseOpenAI(
        api_key=model.api_key,
        timeout=60.0,  # 60 seconds (default is 10 minutes)
    )
    prompt = prompt_template.format(**prompt_kwargs)
    # logger.debug("Prompt: %s", prompt)
    completion = llm.beta.chat.completions.parse(model=model.name,
                                                 messages=[
                                                     {
                                                         "role": "user",
                                                         "content": prompt
                                                     },
                                                 ],
                                                 response_format=output_pydantic_cls,
                                                 temperature=model.temperature)
    resp = completion.choices[0].message
    if (not resp):
        logger.error("Got empty response")
        raise ValueError("Got empty response")
    if (resp.refusal):
        logger.error("Got refusal from model: %s", resp.refusal)
        raise ValueError(json.dumps(resp))

    return resp.parsed


def askOpenAI(model: ModelInfo, prompt_template: str, output_pydantic_cls: Any, prompt_kwargs: Dict[str, Any]) -> Any:
    if model.api_key == "":
        raise AttributeError("No API key set for model")

    llm = OpenAI(
        model=model.name,
        temperature=model.temperature,
        openai_api_key=model.api_key,
    )
    # title = (output_pydantic_cls.schema())["title"]
    program = OpenAIPydanticProgram.from_defaults(
        output_cls=output_pydantic_cls,
        prompt_template_str=prompt_template,
        llm=llm,
        verbose=True,
    )
    # resp = program(llm_kwargs={"tool_choice": title}, **prompt_kwargs)
    resp = program(**prompt_kwargs)
    return resp


def askClaude(model: ModelInfo, prompt_template: str, output_pydantic_cls: Any, prompt_kwargs: Dict[str, Any]) -> Any:
    if model.api_key == "":
        raise AttributeError("No API key set for model")
    llm = Anthropic(
        model=model.name,
        temperature=model.temperature,
        api_key=model.api_key,
    )
    title = (output_pydantic_cls.schema())["title"]
    program = FunctionCallingProgram.from_defaults(
        output_cls=output_pydantic_cls,
        prompt_template_str=prompt_template,
        llm=llm,
        verbose=True,
    )
    resp = program(llm_kwargs={"tool_choice": {"type": "tool", "name": title}}, **prompt_kwargs)
    # resp = program(**prompt_kwargs)
    return resp


def askAI(model: ModelInfo, prompt_template: str, output_pydantic_cls: Any, prompt_kwargs: Dict[str, Any]) -> Any:
    airesp = None
    logger.debug("Started ai call")
    if model.provider == "openai":
        airesp = askOpenAI(model, prompt_template, output_pydantic_cls, prompt_kwargs)
        # airesp = askOpenAIBase(model, prompt_template, output_pydantic_cls, prompt_kwargs)
    elif model.provider == "anthropic":
        airesp = askClaude(model, prompt_template, output_pydantic_cls, prompt_kwargs)
    else:
        raise AttributeError("Invalid provider")
    logger.debug("Done ai call")
    return airesp
