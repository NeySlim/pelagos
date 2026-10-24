# SPDX-License-Identifier: Apache-2.0
"""JsonEnd: the end of a Kea answer is found in one pass, whatever the chunking."""

import json

import pytest

from pelagos.connectors.kea.control_socket import JsonEnd

pytestmark = pytest.mark.unit


def chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


@pytest.mark.parametrize("size", [1, 2, 3, 7, 64, 100000])
def test_end_found_only_at_the_last_byte(size):
    answer = {
        "result": 0,
        "text": 'a "quoted" text with } and ] and \\ backslash',
        "arguments": {"leases": [{"hostname": f"h{i}\\}}"} for i in range(50)]},
    }
    data = json.dumps(answer).encode()
    end = JsonEnd()
    seen = 0
    done_at = None
    for part in chunks(data, size):
        seen += len(part)
        if end.feed(part):
            done_at = seen
            break
    assert done_at is not None and done_at >= len(data) - size + 1
    assert json.loads(data[:done_at]) == answer


def test_list_answer_and_incomplete_input():
    end = JsonEnd()
    assert not end.feed(b'[{"result": 0, "text": "x')
    assert not end.feed(b'"}')
    assert end.feed(b"]")
    assert not JsonEnd().feed(b"")
