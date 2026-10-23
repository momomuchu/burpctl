"""Regression coverage for sensitive query values in raw HTTP request lines."""

from bp.config import redact_data


def test_redact_data_masks_only_sensitive_query_values_in_raw_request_line() -> None:
    request = "GET /reset?token=query-secret&ok=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
    payload = {"request": request}

    result = redact_data(payload)

    assert result == {"request": "GET /reset?token=***&ok=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"}
    assert payload == {"request": request}
