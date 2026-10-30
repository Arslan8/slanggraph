"""Protocol deadlines cover partial frames, including a worker that stalls."""

import subprocess
import sys
import time

import pytest

from langgraph.prebuilt.security._linux_worker import _encode_json_value
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
