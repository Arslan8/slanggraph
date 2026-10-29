"""Run the unmodified upstream sandbox program in the existing Linux worker."""

import io
import json
import sqlite3
import sys
from pathlib import Path


def compute(sandbox_source: str, payload: dict) -> dict:
    attack = payload.pop("attack", None)
    observation = None
    if attack is not None:
        observation = {"attempted": attack["operation"], "effect": False}
        try:
            with sqlite3.connect(attack["database"]) as connection:
                if attack["operation"] == "read_bob":
                    observation["value"] = connection.execute(
                        "SELECT value FROM records WHERE key='bob'"
                    ).fetchone()[0]
                elif attack["operation"] == "update_bob":
                    connection.execute("UPDATE records SET value='COMPROMISED' WHERE key='bob'")
                else:
                    raise ValueError("unsupported attack operation")
                observation["effect"] = True
        except (OSError, sqlite3.Error) as error:
            observation["blocked"] = type(error).__name__
    module = {"__name__": "upstream_sandbox"}
    exec(compile(Path(sandbox_source).read_text(), sandbox_source, "exec"), module)
    if payload.get("sandbox_serialization") is not None:
        from sandbox_codec import VERSIONS, repair_runner

        if payload["sandbox_serialization"] not in VERSIONS:
            raise ValueError("Unsupported sandbox serialization version")
        module["SANDBOX_RUNNER_SCRIPT"] = repair_runner(
            module["SANDBOX_RUNNER_SCRIPT"],
            payload["sandbox_serialization"],
            payload.get("computation_api"),
        )
    original_input, original_output = sys.stdin, sys.stdout
    stream = io.StringIO()
    try:
        sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))
        sys.stdout = stream
        exec(module["SANDBOX_RUNNER_SCRIPT"], {"__name__": "__main__"})
        result = json.loads(stream.getvalue())
        if observation is not None:
            result["attack_observation"] = observation
        return result
    finally:
        sys.stdin, sys.stdout = original_input, original_output
