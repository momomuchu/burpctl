"""bp proxy: the server's NESTED ProxyEntry is flattened to a clean display row.

Contract reconciliation — the Python model now mirrors the Kotlin nested shape
(request/response), and the list view projects id/method/url/status for the table.
"""

from bp.cli import _proxy_rows
from bp.models import ProxyEntry


def test_proxy_entry_model_is_nested() -> None:
    pe = ProxyEntry.model_validate(
        {"id": 5, "request": {"method": "GET", "url": "http://h/p"}, "response": {"statusCode": 404}}
    )
    assert pe.request is not None and pe.request.method == "GET"
    assert pe.response is not None and pe.response.statusCode == 404


def test_proxy_rows_flattens_nested_entry() -> None:
    entries = [
        {"id": 1, "request": {"method": "GET", "url": "http://x/a"}, "response": {"statusCode": 200}}
    ]
    assert _proxy_rows(entries) == [{"id": 1, "method": "GET", "url": "http://x/a", "status": 200}]


def test_proxy_rows_handles_missing_response() -> None:
    rows = _proxy_rows([{"id": 2, "request": {"method": "POST", "url": "http://x/b"}}])
    assert rows == [{"id": 2, "method": "POST", "url": "http://x/b", "status": None}]


def test_proxy_rows_empty() -> None:
    assert _proxy_rows([]) == []
