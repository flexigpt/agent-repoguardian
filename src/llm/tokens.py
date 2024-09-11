from typing import Any, List, Tuple

from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager
from llama_index.core.callbacks import TokenCountingHandler
from llama_index.llms.anthropic import Anthropic
import tiktoken

from .consts import Provider


def get_tokenizer(model_name: str, provider_name: Provider) -> Any:
    tokenizer = None

    if provider_name == Provider.OPENAI:
        tokenizer = tiktoken.encoding_for_model(model_name).encode
    elif provider_name == Provider.ANTHROPIC:
        tokenizer = Anthropic().tokenizer.encode
    else:
        raise ValueError(f"Non supported provider: {provider_name}")
    return tokenizer


def get_tokens_from_string(model_name: str, provider_name: Provider, input_str: str) -> int:
    tokenizer = get_tokenizer(model_name, provider_name)
    return len(tokenizer(input_str))


def get_batches_for_max_tokens(model_name: str, provider_name: Provider, max_tokens: int,
                               instrs: List[str]) -> List[List[Tuple[int, str]]]:
    batches = []
    batch_size = 0
    batch = []

    for instr in instrs:
        t = get_tokens_from_string(model_name, provider_name, instr)
        if batch_size + t > max_tokens:
            batches.append(batch)
            batch = []
            batch_size = 0  # Reset batch_size after appending the batch
        batch.append((t, instr))
        batch_size += t

    if batch:  # Append the last batch if it's not empty
        batches.append(batch)

    return batches


class TokenCounterManager:

    def __init__(self):
        self.token_counter = None

    def set_token_counter(self, model_name: str, provider_name: Provider):
        tokenizer = get_tokenizer(model_name, provider_name)

        self.token_counter = TokenCountingHandler(
            tokenizer=tokenizer,
            verbose=False  # set to true to see usage printed to the console
        )
        Settings.callback_manager = CallbackManager([self.token_counter])

    def reset_counts(self):
        if not self.token_counter:
            return
        self.token_counter.reset_counts()

    def get_counts(self):
        if not self.token_counter:
            return
        return self.token_counter.prompt_llm_token_count, self.token_counter.completion_llm_token_count, self.token_counter.total_llm_token_count
