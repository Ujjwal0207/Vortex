import json
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

@dataclass
class GenAiEvent:
    trace_id: str
    span_id: str
    system: str
    model: str
    prompt: Optional[str] = None
    completion: Optional[str] = None
    tool_name: Optional[str] = None
    tool_parameters: Optional[Dict[str, Any]] = None
    tool_result: Optional[Dict[str, Any]] = None
    model_weights_hash: Optional[str] = None
    supervisor_id: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    timestamp_ns: Optional[int] = None

    def to_bytes(self) -> bytes:
        if not self.timestamp_ns:
            self.timestamp_ns = int(time.time() * 1_000_000_000)
        data = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(data).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "GenAiEvent":
        data = json.loads(raw.decode("utf-8"))
        return cls(**data)

