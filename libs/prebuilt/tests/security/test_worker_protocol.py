"""Protocol deadlines cover partial frames, including a worker that stalls."""

import io
import json
import subprocess
import sys
import time

import pytest

from langgraph.prebuilt.security._linux_worker import _encode_json_value, _write_result
from langgraph.prebuilt.security.linux import _readline_json


def test_partial_frame_cannot_bypass_deadline() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import os,time; os.write(1,b'{'); time.sleep(5)"],
        stdout=subprocess.PIPE,
        bufsize=0,
    )
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            _readline_json(process, 0.2)
        assert time.monotonic() - start < 2
    finally:
        process.kill()
        process.communicate()


@pytest.mark.parametrize("payload", [b"", b'{"status":"ok"}', b"[]\n", b"{}\n{}\n"])
def test_invalid_or_truncated_frames_are_rejected(payload: bytes) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", f"import os; os.write(1, {payload!r})"],
        stdout=subprocess.PIPE,
        bufsize=0,
    )
    try:
        with pytest.raises(ValueError):
            _readline_json(process, 2)
    finally:
        process.communicate()


def test_frame_can_arrive_in_fragments() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,time; os.write(1,b'{'); time.sleep(.05); "
            'os.write(1,b\'"status":"ok"}\\n\')',
        ],
        stdout=subprocess.PIPE,
        bufsize=0,
    )
    try:
        assert _readline_json(process, 2) == {"status": "ok"}
    finally:
        process.communicate()


def test_worker_result_encoder_validates_without_normalized_copy() -> None:
    assert _encode_json_value({"z": (1, True), "a": [None, "text"]}) == (
        '{"a":[null,"text"],"z":[1,true]}'
    )
    with pytest.raises(ValueError, match="string keys"):
        _encode_json_value({1: "unsupported"})
    with pytest.raises(TypeError, match="not supported:set"):
        _encode_json_value(set())


def test_worker_result_telemetry_is_explicit_and_out_of_band() -> None:
    ordinary = io.StringIO()
    _write_result(ordinary, "value")
    assert json.loads(ordinary.getvalue()) == {"result": "value", "status": "ok"}

    instrumented = io.StringIO()
    _write_result(
        instrumented,
        "value",
        body_ns=12,
        timing_ns={"module_execution": 7, "target_call": 3},
    )
    payload = json.loads(instrumented.getvalue())
    assert payload["result"] == "value"
    assert payload["evaluation_timing_ns"]["function_body"] == 12
    assert payload["evaluation_timing_ns"]["module_execution"] == 7
    assert payload["evaluation_timing_ns"]["target_call"] == 3
    assert type(payload["evaluation_timing_ns"]["result_serialization"]) is int
