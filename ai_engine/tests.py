"""
AI Engine regression tests.

These tests protect the workflows that have been fixed during AIDEX
development. They deliberately mock provider execution so running the test
suite never consumes provider quota.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from django.urls import reverse

from cases.models import Case
from evidence.models import Evidence

from .forms import AIAnalysisCancelForm, AIAnalysisRunForm
from .models import AIAnalysis, AIAnalysisLog
from .ocr import extract_evidence_content
from .services import (
    AIAnalysisStateError,
    AIConfigurationError,
    AIServiceError,
    PreparedEvidenceInput,
    build_cache_key_from_values,
    build_openrouter_messages,
    call_configured_provider,
    cancel_analysis,
    get_analysis_provider_name,
    get_ai_provider_name,
    get_configured_model_name,
    get_non_negative_int_setting,
    get_openrouter_max_output_tokens,
    get_openrouter_response_format,
    prepare_evidence_input,
    redact_provider_secrets,
    restore_analysis,
)


User = get_user_model()


class AIEngineWorkflowRegressionTests(TestCase):
    """
    End-to-end regression tests for the AI Engine web workflows.

    No external AI service is called. Provider execution is mocked so the suite is
    safe to run locally and in CI without an API key.
    """

    def setUp(self) -> None:
        self.temp_media_root = tempfile.mkdtemp(
            prefix="aidex_ai_engine_tests_"
        )

        self.settings_override = override_settings(
            MEDIA_ROOT=self.temp_media_root,
            AIDEX_AI_DAILY_USER_LIMIT=0,
        )
        self.settings_override.enable()

        self.admin = User.objects.create_user(
            username="aiadmin",
            email="aiadmin@example.com",
            password="StrongTestPassword123!",
            full_name="AI Administrator",
            badge_id="ADM-AI-001",
            role=User.Role.ADMINISTRATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.investigator = User.objects.create_user(
            username="investigator",
            email="investigator@example.com",
            password="StrongTestPassword123!",
            full_name="Test Investigator",
            badge_id="INV-AI-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.cyber_officer = User.objects.create_user(
            username="cyberofficer",
            email="cyberofficer@example.com",
            password="StrongTestPassword123!",
            full_name="Test Cyber Officer",
            badge_id="CYB-AI-001",
            role=User.Role.CYBER_OFFICER,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.case = Case.objects.create(
            case_title="AI Engine Regression Case",
            description=(
                "Regression-test case used to verify AI Engine workflows."
            ),
            crime_category=Case.CrimeCategory.PHISHING,
            priority=Case.Priority.HIGH,
            created_by=self.investigator,
            assigned_investigator=self.investigator,
        )

        uploaded_file = SimpleUploadedFile(
            "sample-evidence.txt",
            (
                b"Suspicious account activity detected in the test "
                b"evidence file."
            ),
            content_type="text/plain",
        )

        self.evidence = Evidence.objects.create(
            case=self.case,
            evidence_title="Regression Test Evidence",
            description="Evidence used only by the automated test suite.",
            evidence_type=Evidence.EvidenceType.DOCUMENT,
            evidence_file=uploaded_file,
            uploaded_by=self.investigator,
        )

    def tearDown(self) -> None:
        self.settings_override.disable()
        shutil.rmtree(
            self.temp_media_root,
            ignore_errors=True,
        )

    def create_analysis(
        self,
        *,
        title: str = "Regression AI Analysis",
        status: str = AIAnalysis.Status.PENDING,
        request_prompt: str = "Perform a general forensic analysis.",
        created_by=None,
        api_attempts: int = 0,
        max_api_attempts: int = 2,
        quota_exceeded: bool = False,
        is_active: bool = True,
        ai_summary: str = "",
        last_error: str = "",
        evidence=None,
    ) -> AIAnalysis:
        """
        Create one valid AIAnalysis with sensible test defaults.
        """

        creator = created_by or self.investigator

        if status == AIAnalysis.Status.COMPLETED and not ai_summary:
            ai_summary = "Completed test analysis summary."

        if status == AIAnalysis.Status.FAILED and not last_error:
            last_error = "Test provider failure."

        return AIAnalysis.objects.create(
            evidence=evidence or self.evidence,
            title=title,
            analysis_type=AIAnalysis.AnalysisType.GENERAL,
            status=status,
            priority=AIAnalysis.Priority.MEDIUM,
            provider=AIAnalysis.Provider.GEMINI,
            model_name="gemini-flash-latest",
            prompt_version="v1",
            request_prompt=request_prompt,
            created_by=creator,
            api_attempts=api_attempts,
            max_api_attempts=max_api_attempts,
            quota_exceeded=quota_exceeded,
            is_active=is_active,
            ai_summary=ai_summary,
            last_error=last_error,
        )

    @override_settings(
        AI_PROVIDER="OPENROUTER",
        AIDEX_OPENROUTER_MODEL="openai/gpt-4o",
    )
    def test_openrouter_provider_and_model_are_selected(self) -> None:
        self.assertEqual(
            get_ai_provider_name(),
            "OPENROUTER",
        )
        self.assertEqual(
            get_configured_model_name(),
            "openai/gpt-4o",
        )

    @override_settings(
        AI_PROVIDER="OPENROUTER",
        GEMINI_API_KEY="test-gemini-key",
        OPENROUTER_API_KEY="test-openrouter-key",
        AIDEX_GEMINI_MODEL="gemini-flash-latest",
        AIDEX_OPENROUTER_MODEL="openai/gpt-4o",
    )
    def test_analysis_form_offers_both_provider_choices(self) -> None:
        form = AIAnalysisRunForm(
            current_user=self.investigator,
        )
        provider_choices = dict(
            form.fields["provider"].choices
        )

        self.assertIn(
            AIAnalysis.Provider.GEMINI,
            provider_choices,
        )
        self.assertIn(
            AIAnalysis.Provider.OPENROUTER,
            provider_choices,
        )
        self.assertEqual(
            form.initial["provider"],
            AIAnalysis.Provider.OPENROUTER,
        )

    @override_settings(
        AI_PROVIDER="GEMINI",
        OPENROUTER_API_KEY="test-openrouter-key",
        AIDEX_OPENROUTER_MODEL="openai/gpt-4o",
    )
    @patch("ai_engine.services.call_gemini")
    @patch("ai_engine.services.call_openrouter")
    def test_execution_uses_provider_saved_on_analysis(
        self,
        mocked_openrouter,
        mocked_gemini,
    ) -> None:
        analysis = self.create_analysis()
        analysis.provider = AIAnalysis.Provider.OPENROUTER
        analysis.model_name = "openai/gpt-4o"
        analysis.save(
            update_fields=[
                "provider",
                "model_name",
                "updated_date",
            ]
        )
        expected_result = (
            {"summary": "OpenRouter result"},
            "OpenRouter result",
            SimpleNamespace(
                input_tokens=1,
                output_tokens=1,
                total_tokens=2,
            ),
            "request-id",
        )
        mocked_openrouter.return_value = expected_result

        actual_result = call_configured_provider(
            analysis=analysis,
            prompt="Analyze the evidence.",
            prepared_input=PreparedEvidenceInput(
                text="Evidence text",
                source_kind="stored_extracted_text",
            ),
            actor=self.investigator,
        )

        self.assertEqual(
            get_analysis_provider_name(analysis),
            AIAnalysis.Provider.OPENROUTER,
        )
        self.assertEqual(actual_result, expected_result)
        mocked_openrouter.assert_called_once()
        mocked_gemini.assert_not_called()

    @override_settings(AI_PROVIDER="UNSUPPORTED")
    def test_unknown_provider_is_rejected(self) -> None:
        with self.assertRaises(AIConfigurationError):
            get_ai_provider_name()

    @override_settings(
        OPENROUTER_API_KEY="test-openrouter-secret-value",
    )
    def test_provider_error_redaction_removes_api_key(self) -> None:
        redacted = redact_provider_secrets(
            "api_key=test-openrouter-secret-value"
        )

        self.assertNotIn(
            "test-openrouter-secret-value",
            redacted,
        )
        self.assertIn("[REDACTED]", redacted)

    def test_openrouter_text_request_and_json_schema(self) -> None:
        prepared_input = PreparedEvidenceInput(
            text="Evidence text",
            source_kind="stored_extracted_text",
        )
        messages, extra_body = build_openrouter_messages(
            prompt="Analyze the evidence.",
            prepared_input=prepared_input,
        )
        response_format = get_openrouter_response_format(
            use_response_schema=True,
        )

        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[1]["role"], "user")
        self.assertEqual(
            messages[1]["content"],
            "Analyze the evidence.",
        )
        self.assertEqual(extra_body, {})
        self.assertEqual(
            response_format["type"],
            "json_schema",
        )

    @override_settings(
        AIDEX_AI_MAX_OUTPUT_TOKENS=4096,
        AIDEX_OPENROUTER_MAX_OUTPUT_TOKENS=3072,
    )
    def test_openrouter_uses_independent_output_token_budget(self) -> None:
        self.assertEqual(
            get_openrouter_max_output_tokens(),
            3072,
        )

    def test_openrouter_pdf_request_uses_file_parser(self) -> None:
        pdf_path = Path(self.temp_media_root) / "openrouter-test.pdf"
        pdf_bytes = b"%PDF-1.7\n% OpenRouter regression test\n%%EOF\n"
        pdf_path.write_bytes(pdf_bytes)
        prepared_input = PreparedEvidenceInput(
            text="PDF evidence metadata",
            source_kind="pdf_multimodal",
            mime_type="application/pdf",
            media_path=str(pdf_path),
            media_size_bytes=len(pdf_bytes),
        )

        messages, extra_body = build_openrouter_messages(
            prompt="Analyze this PDF.",
            prepared_input=prepared_input,
        )
        content = messages[1]["content"]

        self.assertEqual(content[0]["type"], "text")
        self.assertEqual(content[1]["type"], "file")
        self.assertTrue(
            content[1]["file"]["file_data"].startswith(
                "data:application/pdf;base64,"
            )
        )
        self.assertEqual(
            extra_body["plugins"][0]["id"],
            "file-parser",
        )

    def test_encrypted_text_extraction_removes_temporary_plaintext(
        self,
    ) -> None:
        before_paths = set(
            Path(tempfile.gettempdir()).glob(
                "aidex-decrypted-*"
            )
        )

        result = extract_evidence_content(
            self.evidence
        )

        after_paths = set(
            Path(tempfile.gettempdir()).glob(
                "aidex-decrypted-*"
            )
        )

        self.assertIn(
            "Suspicious account activity",
            result.text,
        )
        self.assertEqual(after_paths, before_paths)

    def test_prepared_encrypted_media_is_removed_after_cleanup(
        self,
    ) -> None:
        pdf_evidence = Evidence.objects.create(
            case=self.case,
            evidence_title="Encrypted PDF Evidence",
            description="PDF evidence used to verify temporary cleanup.",
            evidence_type=Evidence.EvidenceType.DOCUMENT,
            evidence_file=SimpleUploadedFile(
                "encrypted-sample.pdf",
                b"%PDF-1.7\n% AIDEX encrypted media sample\n%%EOF\n",
                content_type="application/pdf",
            ),
            uploaded_by=self.investigator,
        )
        analysis = self.create_analysis(
            title="Encrypted PDF Analysis",
            evidence=pdf_evidence,
        )

        prepared_input = prepare_evidence_input(
            analysis
        )
        temporary_path = prepared_input.media_path

        self.assertTrue(temporary_path)
        self.assertTrue(os.path.isfile(temporary_path))

        prepared_input.cleanup()

        self.assertFalse(os.path.exists(temporary_path))

    # ------------------------------------------------------------------
    # Cache identity
    # ------------------------------------------------------------------

    @override_settings(AIDEX_AI_MAX_RETRIES=0)
    def test_zero_provider_retries_is_respected(self) -> None:
        self.assertEqual(
            get_non_negative_int_setting(
                "AIDEX_AI_MAX_RETRIES",
                2,
            ),
            0,
        )

    def test_cache_key_changes_when_prompt_model_or_pipeline_changes(
        self,
    ) -> None:
        base_kwargs = {
            "evidence_hash": self.evidence.sha256_hash,
            "analysis_type": AIAnalysis.AnalysisType.GENERAL,
            "prompt_version": "v1",
            "request_prompt": "Analyze this evidence.",
            "provider": AIAnalysis.Provider.GEMINI,
            "model_name": "gemini-flash-latest",
            "pipeline_version": "multimodal-v2",
        }

        base_key = build_cache_key_from_values(
            **base_kwargs
        )

        changed_prompt_key = build_cache_key_from_values(
            **{
                **base_kwargs,
                "request_prompt": "Analyze this evidence for phishing.",
            }
        )

        changed_model_key = build_cache_key_from_values(
            **{
                **base_kwargs,
                "model_name": "another-model",
            }
        )

        changed_pipeline_key = build_cache_key_from_values(
            **{
                **base_kwargs,
                "pipeline_version": "multimodal-v3",
            }
        )

        self.assertEqual(
            len(base_key),
            64,
        )
        self.assertNotEqual(
            base_key,
            changed_prompt_key,
        )
        self.assertNotEqual(
            base_key,
            changed_model_key,
        )
        self.assertNotEqual(
            base_key,
            changed_pipeline_key,
        )

    # ------------------------------------------------------------------
    # Retry
    # ------------------------------------------------------------------

    def test_failed_analysis_can_be_manually_retried_at_max_attempts(
        self,
    ) -> None:
        analysis = self.create_analysis(
            status=AIAnalysis.Status.FAILED,
            api_attempts=2,
            max_api_attempts=2,
        )

        self.assertTrue(
            analysis.retry_budget_exhausted
        )
        self.assertTrue(
            analysis.can_retry
        )

    def test_retry_resets_attempt_counter_and_returns_to_pending(
        self,
    ) -> None:
        analysis = self.create_analysis(
            status=AIAnalysis.Status.FAILED,
            api_attempts=2,
            max_api_attempts=2,
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_retry",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertEqual(
            analysis.status,
            AIAnalysis.Status.PENDING,
        )
        self.assertEqual(
            analysis.api_attempts,
            0,
        )
        self.assertEqual(
            analysis.last_error,
            "",
        )
        self.assertFalse(
            analysis.quota_exceeded
        )
        self.assertTrue(
            AIAnalysisLog.objects.filter(
                analysis=analysis,
                event_type=AIAnalysisLog.EventType.RETRY,
            ).exists()
        )

    # ------------------------------------------------------------------
    # Cancel
    # ------------------------------------------------------------------

    def test_cancel_form_rejects_missing_confirmation(
        self,
    ) -> None:
        form = AIAnalysisCancelForm(
            data={
                "cancellation_reason": (
                    "This request is no longer required."
                ),
            }
        )

        self.assertFalse(
            form.is_valid()
        )
        self.assertIn(
            "confirmation",
            form.errors,
        )

    def test_cancel_workflow_marks_analysis_cancelled_and_logs_reason(
        self,
    ) -> None:
        analysis = self.create_analysis()

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_cancel",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            ),
            data={
                "confirmation": "on",
                "cancellation_reason": (
                    "The evidence request was entered by mistake."
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertEqual(
            analysis.status,
            AIAnalysis.Status.CANCELLED,
        )
        self.assertIsNotNone(
            analysis.completed_at
        )

        cancel_log = AIAnalysisLog.objects.filter(
            analysis=analysis,
            event_type=AIAnalysisLog.EventType.CANCELLED,
        ).latest(
            "created_date"
        )

        self.assertIn(
            "mistake",
            (
                cancel_log.metadata.get(
                    "reason",
                    ""
                )
            ).lower(),
        )

    # ------------------------------------------------------------------
    # Archive / Restore
    # ------------------------------------------------------------------

    def test_archive_then_restore_analysis(
        self,
    ) -> None:
        analysis = self.create_analysis()

        self.client.force_login(
            self.admin
        )

        archive_response = self.client.post(
            reverse(
                "ai_engine:analysis_archive",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            ),
            data={
                "confirmation": "on",
                "reason": (
                    "Archiving this record after regression verification."
                ),
            },
        )

        self.assertEqual(
            archive_response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertFalse(
            analysis.is_active
        )
        self.assertTrue(
            AIAnalysisLog.objects.filter(
                analysis=analysis,
                event_type=AIAnalysisLog.EventType.ARCHIVED,
            ).exists()
        )

        restore_response = self.client.post(
            reverse(
                "ai_engine:analysis_restore",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            )
        )

        self.assertEqual(
            restore_response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertTrue(
            analysis.is_active
        )
        self.assertTrue(
            AIAnalysisLog.objects.filter(
                analysis=analysis,
                event_type=AIAnalysisLog.EventType.RESTORED,
            ).exists()
        )

    # ------------------------------------------------------------------
    # Duplicate-run protection
    # ------------------------------------------------------------------

    @patch("ai_engine.views.execute_analysis")
    def test_identical_prompt_already_queued_blocks_duplicate_run(
        self,
        mocked_execute,
    ) -> None:
        target = self.create_analysis(
            title="Target Pending Analysis",
            request_prompt="Analyze the phishing indicators.",
        )

        self.create_analysis(
            title="Already Queued Analysis",
            status=AIAnalysis.Status.QUEUED,
            request_prompt="Analyze the phishing indicators.",
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_run",
                kwargs={
                    "analysis_id": target.pk,
                },
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        target.refresh_from_db()

        self.assertEqual(
            target.status,
            AIAnalysis.Status.PENDING,
        )

        mocked_execute.assert_not_called()

    @patch("ai_engine.views.execute_analysis")
    def test_different_prompt_does_not_trigger_duplicate_block(
        self,
        mocked_execute,
    ) -> None:
        target = self.create_analysis(
            title="Target Prompt Analysis",
            request_prompt="Analyze account takeover indicators.",
        )

        self.create_analysis(
            title="Different Prompt Queued Analysis",
            status=AIAnalysis.Status.QUEUED,
            request_prompt="Analyze malware indicators.",
        )

        mocked_execute.return_value = SimpleNamespace(
            completed=True,
            cached=False,
            provider_called=True,
            error=None,
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_run",
                kwargs={
                    "analysis_id": target.pk,
                },
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        target.refresh_from_db()

        self.assertEqual(
            target.status,
            AIAnalysis.Status.QUEUED,
        )

        mocked_execute.assert_called_once()

    # ------------------------------------------------------------------
    # Safe user-facing errors
    # ------------------------------------------------------------------

    @patch("ai_engine.views.execute_analysis")
    def test_provider_error_details_are_not_exposed_to_browser(
        self,
        mocked_execute,
    ) -> None:
        analysis = self.create_analysis(
            title="Safe Error Message Analysis",
            request_prompt="Analyze this evidence securely.",
        )

        secret_detail = (
            "INTERNAL_PROVIDER_ERROR api_key=SHOULD_NOT_BE_DISPLAYED"
        )

        mocked_execute.side_effect = AIServiceError(
            secret_detail
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_run",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        displayed_messages = " ".join(
            str(message)
            for message in get_messages(
                response.wsgi_request
            )
        )

        self.assertNotIn(
            secret_detail,
            displayed_messages,
        )
        self.assertNotIn(
            "SHOULD_NOT_BE_DISPLAYED",
            displayed_messages,
        )
        self.assertIn(
            "could not be executed",
            displayed_messages.lower(),
        )

    # ------------------------------------------------------------------
    # Human review
    # ------------------------------------------------------------------

    def test_cyber_officer_or_admin_review_records_reviewer(
        self,
    ) -> None:
        analysis = self.create_analysis(
            status=AIAnalysis.Status.COMPLETED,
            ai_summary="Completed forensic result for human review.",
        )

        self.client.force_login(
            self.admin
        )

        review_page = self.client.get(
            reverse(
                "ai_engine:analysis_review",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            )
        )

        self.assertEqual(
            review_page.status_code,
            200,
        )

        review_version = review_page.context[
            "review_version"
        ]

        self.assertTrue(
            review_version
        )
        self.assertContains(
            review_page,
            'name="review_version"',
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_review",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            ),
            data={
                "review_version": review_version,
                "review_notes": (
                    "The findings are useful and require investigator "
                    "verification before evidentiary use."
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertEqual(
            analysis.reviewed_by,
            self.admin,
        )
        self.assertIsNotNone(
            analysis.reviewed_at
        )
        self.assertTrue(
            AIAnalysisLog.objects.filter(
                analysis=analysis,
                event_type=AIAnalysisLog.EventType.REVIEWED,
            ).exists()
        )

    def test_stale_human_review_cannot_overwrite_newer_review(
        self,
    ) -> None:
        analysis = self.create_analysis(
            status=AIAnalysis.Status.COMPLETED,
            ai_summary="Completed result for stale-review protection.",
        )

        self.client.force_login(
            self.admin
        )

        stale_page = self.client.get(
            reverse(
                "ai_engine:analysis_review",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            )
        )

        stale_token = stale_page.context[
            "review_version"
        ]

        newer_review_time = timezone.now()

        AIAnalysis.objects.filter(
            pk=analysis.pk,
        ).update(
            review_notes=(
                "A newer review was already saved by the cyber officer."
            ),
            reviewed_by_id=self.cyber_officer.pk,
            reviewed_at=newer_review_time,
            updated_date=newer_review_time,
        )

        response = self.client.post(
            reverse(
                "ai_engine:analysis_review",
                kwargs={
                    "analysis_id": analysis.pk,
                },
            ),
            data={
                "review_version": stale_token,
                "review_notes": (
                    "This stale review must not replace the newer review."
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        analysis.refresh_from_db()

        self.assertEqual(
            analysis.reviewed_by,
            self.cyber_officer,
        )
        self.assertEqual(
            analysis.review_notes,
            (
                "A newer review was already saved by the cyber officer."
            ),
        )

    # ------------------------------------------------------------------
    # Final concurrency / lifecycle edge guards
    # ------------------------------------------------------------------

    def test_cancel_service_cannot_overwrite_processing_state(
        self,
    ) -> None:
        """
        A stale Pending object must not cancel an analysis after execution
        has already claimed PROCESSING state.
        """

        analysis = self.create_analysis(
            status=AIAnalysis.Status.PENDING,
        )

        stale_analysis = AIAnalysis.objects.get(
            pk=analysis.pk
        )

        transition_time = timezone.now()

        AIAnalysis.objects.filter(
            pk=analysis.pk
        ).update(
            status=AIAnalysis.Status.PROCESSING,
            started_at=transition_time,
            updated_date=transition_time,
        )

        with self.assertRaises(
            AIAnalysisStateError
        ):
            cancel_analysis(
                stale_analysis,
                actor=self.admin,
                reason="Concurrent admin cancellation regression test.",
            )

        analysis.refresh_from_db()

        self.assertEqual(
            analysis.status,
            AIAnalysis.Status.PROCESSING,
        )
        self.assertFalse(
            AIAnalysisLog.objects.filter(
                analysis=analysis,
                event_type=AIAnalysisLog.EventType.CANCELLED,
            ).exists()
        )

    def test_restore_service_requires_active_evidence(
        self,
    ) -> None:
        analysis = self.create_analysis(
            status=AIAnalysis.Status.COMPLETED,
            ai_summary="Completed analysis for restore safety regression.",
            is_active=False,
        )

        Evidence.objects.filter(
            pk=self.evidence.pk
        ).update(
            is_active=False,
            updated_date=timezone.now(),
        )

        self.evidence.refresh_from_db()
        analysis.refresh_from_db()

        with self.assertRaises(
            AIAnalysisStateError
        ):
            restore_analysis(
                analysis,
                actor=self.admin,
            )

        analysis.refresh_from_db()

        self.assertFalse(
            analysis.is_active
        )
