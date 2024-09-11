from enum import Enum
from typing import Dict

from pydantic import BaseModel
from pydantic import Field


class Provider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class ModelInfo(BaseModel):
    name: str
    provider: Provider
    max_prompt_length: int
    temperature: float = Field(default=0.0)
    api_key: str = Field(default="")
    engine: str = Field(default="")


MODEL_INFO: Dict[str, ModelInfo] = {
    "gpt-4o":
        ModelInfo(name="gpt-4o", provider=Provider.OPENAI, max_prompt_length=8000),
    "gpt-4o-snap":
        ModelInfo(name="gpt-4o-2024-08-06", provider=Provider.OPENAI, max_prompt_length=8000),
    "gpt-4o-mini":
        ModelInfo(name="gpt-4o-mini", provider=Provider.OPENAI, max_prompt_length=8000),
    "gpt-4":
        ModelInfo(name="gpt-4", provider=Provider.OPENAI, max_prompt_length=4000),
    "gpt-3.5-turbo":
        ModelInfo(name="gpt-3.5-turbo", provider=Provider.OPENAI, max_prompt_length=2400),
    "claude-3-5-sonnet":
        ModelInfo(name="claude-3-5-sonnet-20240620", provider=Provider.ANTHROPIC, max_prompt_length=8000),
    "claude-3-opus":
        ModelInfo(name="claude-3-opus-20240229", provider=Provider.ANTHROPIC, max_prompt_length=8000),
    "claude-3-sonnet":
        ModelInfo(name="claude-3-sonnet-20240229", provider=Provider.ANTHROPIC, max_prompt_length=8000),
    "claude-3-haiku":
        ModelInfo(name="claude-3-haiku-20240307", provider=Provider.ANTHROPIC, max_prompt_length=8000),
}
