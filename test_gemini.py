"""Test the exact Gemini model configured for the AIDEX application."""

from __future__ import annotations

import os
import sys
from typing import Any

import django
from django.conf import settings
from google import genai


def print_header() -> None:
    print("=" * 60)
    print("AIDEX - Configured Gemini Connection Test")
    print("=" * 60)


def load_aidex_configuration() -> tuple[str, str]:
    """Load the same Django settings used by the website."""

    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE",
        "aidex.settings",
    )
    django.setup()

    api_key = str(
        settings.GEMINI_API_KEY
        or ""
    ).strip()
    model_name = str(
        settings.AIDEX_GEMINI_MODEL
        or ""
    ).strip()

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    if not model_name:
        raise RuntimeError(
            "AIDEX_GEMINI_MODEL is not configured."
        )

    return api_key, model_name


def get_status_code(error: Exception) -> int | None:
    """Return a provider status code without exposing response secrets."""

    for attribute_name in (
        "status_code",
        "code",
    ):
        raw_value: Any = getattr(
            error,
            attribute_name,
            None,
        )

        try:
            return int(raw_value)
        except (
            TypeError,
            ValueError,
        ):
            continue

    return None


def get_safe_error_hint(
    status_code: int | None,
) -> str:
    """Map common provider failures to safe troubleshooting guidance."""

    if status_code in {
        401,
        403,
    }:
        return "Check the Gemini API key and its project permissions."

    if status_code in {
        400,
        404,
    }:
        return "Check that the configured Gemini model name is available."

    if status_code == 429:
        return "Gemini quota or rate limit was reached. Try again later."

    if status_code == 503:
        return "Gemini is temporarily overloaded. Try again after a short wait."

    return "Check network access, the API key and the configured model."


def test_connection(
    api_key: str,
    model_name: str,
) -> bool:
    """Send one minimal request to the exact model used by AIDEX."""

    try:
        client = genai.Client(
            api_key=api_key
        )
        response = client.models.generate_content(
            model=model_name,
            contents="Reply only OK",
        )
        response_text = str(
            getattr(
                response,
                "text",
                "",
            )
            or ""
        ).strip()

        if not response_text:
            print("\nConnection Status: FAILED")
            print("Gemini returned an empty response.")
            return False

        print("\nConnection Status: SUCCESS")
        print(f"Configured Model: {model_name}")
        print(f"Response: {response_text}")
        return True

    except Exception as error:
        status_code = get_status_code(
            error
        )

        print("\nConnection Status: FAILED")
        print(f"Configured Model: {model_name}")
        print(
            "Provider Error: "
            f"{error.__class__.__name__}"
            + (
                f" (HTTP {status_code})"
                if status_code is not None
                else ""
            )
        )
        print(
            get_safe_error_hint(
                status_code
            )
        )
        return False


def main() -> None:
    print_header()

    try:
        api_key, model_name = (
            load_aidex_configuration()
        )
    except RuntimeError as error:
        print(f"\nConfiguration Error: {error}")
        raise SystemExit(1) from error

    if not test_connection(
        api_key,
        model_name,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
