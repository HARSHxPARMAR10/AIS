"""
AIDEX AI Engine Forms

Professional forms for creating, filtering, reviewing and archiving
AI-assisted forensic analyses.

The forms are designed for a cost-conscious multi-provider workflow:

- AI calls are only triggered after an explicit user action.
- Cached results may be reused when the evidence hash, analysis type and
  prompt version have not changed.
- Archived evidence cannot be analyzed.
- Duplicate active analyses are prevented unless re-analysis is explicitly
  requested.
- Provider is explicitly selected; retry and token fields remain controlled.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q, QuerySet

from cases.models import Case
from evidence.models import Evidence

from .models import AIAnalysis
from .services import (
    AIConfigurationError,
    build_cache_key_from_values,
    get_configured_model_name,
)


User = get_user_model()


# ==========================================================
# Role Configuration
# ==========================================================

ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_INVESTIGATOR = "INVESTIGATOR"
ROLE_CYBER_OFFICER = "CYBER_OFFICER"


ROLE_ALIASES = {
    "ADMIN": ROLE_ADMINISTRATOR,
    "ADMINISTRATOR": ROLE_ADMINISTRATOR,
    "SUPERADMIN": ROLE_ADMINISTRATOR,
    "SUPER_ADMIN": ROLE_ADMINISTRATOR,
    "INVESTIGATOR": ROLE_INVESTIGATOR,
    "CYBEROFFICER": ROLE_CYBER_OFFICER,
    "CYBER_OFFICER": ROLE_CYBER_OFFICER,
    "CYBER OFFICER": ROLE_CYBER_OFFICER,
    "OFFICER": ROLE_CYBER_OFFICER,
}


# ==========================================================
# Prompt Configuration
# ==========================================================

PROMPT_GENERAL = "GENERAL_FORENSIC_REVIEW"
PROMPT_OCR = "OCR_TEXT_EXTRACTION"
PROMPT_DOCUMENT = "DOCUMENT_EVIDENCE_REVIEW"
PROMPT_IMAGE = "IMAGE_EVIDENCE_REVIEW"
PROMPT_VIDEO = "VIDEO_EVIDENCE_REVIEW"
PROMPT_AUDIO = "AUDIO_EVIDENCE_REVIEW"
PROMPT_EMAIL = "EMAIL_EVIDENCE_REVIEW"
PROMPT_CHAT = "CHAT_EVIDENCE_REVIEW"
PROMPT_LOG = "LOG_EVIDENCE_REVIEW"
PROMPT_THREAT = "THREAT_ASSESSMENT"
PROMPT_CUSTOM = "CUSTOM"


PROMPT_TEMPLATE_CHOICES = [
    (
        PROMPT_GENERAL,
        "General Forensic Review",
    ),
    (
        PROMPT_OCR,
        "OCR Text Extraction",
    ),
    (
        PROMPT_DOCUMENT,
        "Document Evidence Review",
    ),
    (
        PROMPT_IMAGE,
        "Image Evidence Review",
    ),
    (
        PROMPT_VIDEO,
        "Video Evidence Review",
    ),
    (
        PROMPT_AUDIO,
        "Audio Evidence Review",
    ),
    (
        PROMPT_EMAIL,
        "Email Evidence Review",
    ),
    (
        PROMPT_CHAT,
        "Chat Evidence Review",
    ),
    (
        PROMPT_LOG,
        "Log Evidence Review",
    ),
    (
        PROMPT_THREAT,
        "Threat Assessment",
    ),
    (
        PROMPT_CUSTOM,
        "Custom Prompt",
    ),
]


PROMPT_VERSION_CHOICES = [
    (
        "v1",
        "Version 1",
    ),
]


# ==========================================================
# Utility Functions
# ==========================================================

def normalize_role(
    role_value: Any,
) -> str:
    """
    Convert role values to the standard AIDEX format.
    """

    normalized_role = (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return ROLE_ALIASES.get(
        normalized_role,
        normalized_role,
    )


def get_user_role(
    user: Any,
) -> str:
    """
    Return the normalized AIDEX role for a user.
    """

    if getattr(
        user,
        "is_superuser",
        False,
    ):
        return ROLE_ADMINISTRATOR

    return normalize_role(
        getattr(
            user,
            "role",
            "",
        )
    )


def get_accessible_evidence_queryset(
    user: Any,
    include_evidence: Evidence | None = None,
) -> QuerySet[Evidence]:
    """
    Return evidence that the current user may analyze.

    Administrator and Cyber Officer:
        All active evidence.

    Investigator:
        Active evidence uploaded by the investigator or linked to a case
        created by or assigned to the investigator.

    Existing evidence may be included while editing an analysis so the saved
    relation can still render even if access conditions later changed.
    """

    queryset = Evidence.objects.select_related(
        "case",
        "case__created_by",
        "case__assigned_investigator",
        "uploaded_by",
        "verified_by",
    )

    if not getattr(
        user,
        "is_authenticated",
        False,
    ):
        return queryset.none()

    role = get_user_role(
        user
    )

    active_filter = Q(
        is_active=True
    )

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        access_filter = active_filter

    elif role == ROLE_INVESTIGATOR:
        access_filter = active_filter & (
            Q(uploaded_by=user)
            | Q(case__created_by=user)
            | Q(case__assigned_investigator=user)
        )

    else:
        return queryset.none()

    if include_evidence is not None:
        access_filter = (
            access_filter
            | Q(pk=include_evidence.pk)
        )

    return (
        queryset
        .filter(access_filter)
        .distinct()
        .order_by(
            "-uploaded_date"
        )
    )


def get_accessible_case_queryset(
    user: Any,
) -> QuerySet[Case]:
    """
    Return cases visible through accessible evidence.
    """

    evidence_queryset = get_accessible_evidence_queryset(
        user
    )

    return (
        Case.objects
        .filter(
            evidence_items__in=evidence_queryset
        )
        .distinct()
        .order_by(
            "-created_date"
        )
    )


def get_active_user_queryset() -> QuerySet:
    """
    Return active users for filter forms.
    """

    queryset = User.objects.filter(
        is_active=True
    )

    account_status = getattr(
        User,
        "AccountStatus",
        None,
    )

    if account_status is not None:
        queryset = queryset.filter(
            account_status=account_status.ACTIVE
        )

    return queryset.order_by(
        "full_name",
        "username",
    )


def normalize_meaningful_text(
    value: Any,
) -> str:
    """
    Collapse repeated whitespace in user-entered text.
    """

    return " ".join(
        str(value or "")
        .strip()
        .split()
    )


def has_meaningful_content(
    value: str,
    *,
    minimum_alphanumeric: int = 6,
) -> bool:
    """
    Return True when text contains enough letters or numbers.
    """

    return sum(
        character.isalnum()
        for character in value
    ) >= minimum_alphanumeric


def analysis_type_matches_evidence(
    analysis_type: str,
    evidence: Evidence,
) -> bool:
    """
    Return whether the selected analysis type suits the evidence type.

    General, metadata, integrity, keyword and threat analyses are accepted
    for every evidence category.
    """

    universal_types = {
        AIAnalysis.AnalysisType.GENERAL,
        AIAnalysis.AnalysisType.METADATA,
        AIAnalysis.AnalysisType.FILE_INTEGRITY,
        AIAnalysis.AnalysisType.KEYWORD_EXTRACTION,
        AIAnalysis.AnalysisType.THREAT_ASSESSMENT,
        AIAnalysis.AnalysisType.CUSTOM,
    }

    if analysis_type in universal_types:
        return True

    allowed_mapping = {
        Evidence.EvidenceType.IMAGE: {
            AIAnalysis.AnalysisType.IMAGE,
            AIAnalysis.AnalysisType.FACE_DETECTION,
            AIAnalysis.AnalysisType.OBJECT_DETECTION,
        },
        Evidence.EvidenceType.SCREENSHOT: {
            AIAnalysis.AnalysisType.IMAGE,
            AIAnalysis.AnalysisType.OCR,
            AIAnalysis.AnalysisType.FACE_DETECTION,
            AIAnalysis.AnalysisType.OBJECT_DETECTION,
        },
        Evidence.EvidenceType.VIDEO: {
            AIAnalysis.AnalysisType.VIDEO,
            AIAnalysis.AnalysisType.FACE_DETECTION,
            AIAnalysis.AnalysisType.OBJECT_DETECTION,
            AIAnalysis.AnalysisType.AUDIO,
        },
        Evidence.EvidenceType.AUDIO: {
            AIAnalysis.AnalysisType.AUDIO,
        },
        Evidence.EvidenceType.DOCUMENT: {
            AIAnalysis.AnalysisType.DOCUMENT,
            AIAnalysis.AnalysisType.OCR,
        },
        Evidence.EvidenceType.EMAIL: {
            AIAnalysis.AnalysisType.EMAIL,
            AIAnalysis.AnalysisType.DOCUMENT,
            AIAnalysis.AnalysisType.OCR,
        },
        Evidence.EvidenceType.CHAT: {
            AIAnalysis.AnalysisType.CHAT,
            AIAnalysis.AnalysisType.DOCUMENT,
            AIAnalysis.AnalysisType.OCR,
        },
        Evidence.EvidenceType.LOG_FILE: {
            AIAnalysis.AnalysisType.LOG,
            AIAnalysis.AnalysisType.NETWORK,
            AIAnalysis.AnalysisType.MALWARE,
        },
        Evidence.EvidenceType.ARCHIVE: {
            AIAnalysis.AnalysisType.MALWARE,
        },
        Evidence.EvidenceType.OTHER: {
            AIAnalysis.AnalysisType.DOCUMENT,
            AIAnalysis.AnalysisType.OCR,
            AIAnalysis.AnalysisType.MALWARE,
            AIAnalysis.AnalysisType.NETWORK,
        },
    }

    return analysis_type in allowed_mapping.get(
        evidence.evidence_type,
        set(),
    )


# ==========================================================
# AI Analysis Run Form
# ==========================================================

class AIAnalysisRunForm(forms.ModelForm):
    """
    Create a new AI analysis request.

    The view must pass current_user:

        form = AIAnalysisRunForm(
            request.POST or None,
            current_user=request.user,
        )

    The actual provider call should happen in a dedicated service layer after
    the form is valid and the model instance is saved.
    """

    prompt_template = forms.ChoiceField(
        label="Prompt Template",
        choices=PROMPT_TEMPLATE_CHOICES,
        initial=PROMPT_GENERAL,
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
        help_text=(
            "Choose a predefined forensic prompt or select Custom Prompt."
        ),
    )

    custom_prompt = forms.CharField(
        required=False,
        label="Custom Prompt",
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 6,
                "placeholder": (
                    "Describe the exact forensic questions the AI should answer."
                ),
            }
        ),
        help_text=(
            "Required only when Custom Prompt is selected."
        ),
    )

    prompt_version = forms.ChoiceField(
        label="Prompt Version",
        choices=PROMPT_VERSION_CHOICES,
        initial="v1",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
        help_text=(
            "Prompt version is stored for repeatability and audit review."
        ),
    )

    use_cached_result = forms.BooleanField(
        required=False,
        initial=True,
        label="Reuse Matching Cached Result",
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "role": "switch",
            }
        ),
        help_text=(
            "Reuse a valid completed analysis when evidence hash, type and "
            "prompt version match."
        ),
    )

    force_reanalysis = forms.BooleanField(
        required=False,
        initial=False,
        label="Force New Analysis",
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "role": "switch",
            }
        ),
        help_text=(
            "Ignore matching cached results and create a fresh provider request."
        ),
    )

    confirm_external_processing = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this evidence is approved for external AI processing."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
        help_text=(
            "Sensitive evidence should be sanitized or excluded before external "
            "provider processing."
        ),
    )

    class Meta:
        model = AIAnalysis

        fields = [
            "evidence",
            "title",
            "analysis_type",
            "provider",
            "priority",
        ]

        labels = {
            "evidence": "Related Evidence",
            "title": "Analysis Title",
            "analysis_type": "Analysis Type",
            "provider": "AI Provider",
            "priority": "Processing Priority",
        }

        help_texts = {
            "evidence": (
                "Select the active evidence record to analyze."
            ),
            "title": (
                "Enter a clear title describing the analysis objective."
            ),
            "analysis_type": (
                "Choose the AI workflow that best matches the evidence."
            ),
            "provider": (
                "Choose local demo analysis, Google Gemini, or ChatGPT "
                "through OpenRouter for this analysis."
            ),
            "priority": (
                "Priority affects queue order, not provider cost."
            ),
        }

        widgets = {
            "evidence": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": (
                        "Example: Suspicious Email Threat Assessment"
                    ),
                    "autocomplete": "off",
                    "maxlength": "200",
                }
            ),
            "analysis_type": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "provider": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "priority": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }

    def __init__(
        self,
        *args: Any,
        current_user: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Configure accessible evidence and role-aware priority choices.
        """

        super().__init__(
            *args,
            **kwargs,
        )

        self.current_user = current_user

        provider_choices = [
            (
                AIAnalysis.Provider.LOCAL,
                AIAnalysis.Provider.LOCAL.label,
            ),
            (
                AIAnalysis.Provider.GEMINI,
                AIAnalysis.Provider.GEMINI.label,
            ),
            (
                AIAnalysis.Provider.OPENROUTER,
                AIAnalysis.Provider.OPENROUTER.label,
            ),
        ]
        self.fields["provider"].choices = provider_choices

        configured_default_provider = str(
            getattr(settings, "AI_PROVIDER", "GEMINI")
            or "GEMINI"
        ).strip().upper()

        if configured_default_provider not in {
            value for value, _ in provider_choices
        }:
            configured_default_provider = AIAnalysis.Provider.LOCAL

        if not self.is_bound:
            self.initial["provider"] = configured_default_provider

        self.fields[
            "evidence"
        ].queryset = get_accessible_evidence_queryset(
            user=current_user
        )

        self.fields[
            "evidence"
        ].empty_label = "Select evidence"

        self.fields[
            "title"
        ].widget.attrs.update({
            "autofocus": True,
        })

        if get_user_role(
            current_user
        ) == ROLE_INVESTIGATOR:
            self.fields[
                "priority"
            ].choices = [
                (
                    AIAnalysis.Priority.LOW,
                    AIAnalysis.Priority.LOW.label,
                ),
                (
                    AIAnalysis.Priority.MEDIUM,
                    AIAnalysis.Priority.MEDIUM.label,
                ),
                (
                    AIAnalysis.Priority.HIGH,
                    AIAnalysis.Priority.HIGH.label,
                ),
            ]

    def clean_evidence(
        self,
    ) -> Evidence:
        """
        Ensure selected evidence is active and accessible.
        """

        evidence = self.cleaned_data.get(
            "evidence"
        )

        if evidence is None:
            raise forms.ValidationError(
                "Please select evidence for analysis."
            )

        accessible_evidence = get_accessible_evidence_queryset(
            user=self.current_user
        )

        if not accessible_evidence.filter(
            pk=evidence.pk
        ).exists():
            raise forms.ValidationError(
                "You do not have access to the selected evidence."
            )

        if not evidence.is_active:
            raise forms.ValidationError(
                "Archived evidence cannot be analyzed."
            )

        if not evidence.evidence_file:
            raise forms.ValidationError(
                "The selected evidence does not contain an uploaded file."
            )

        if not evidence.sha256_hash:
            raise forms.ValidationError(
                (
                    "The selected evidence does not have a SHA-256 hash. "
                    "Complete evidence processing before AI analysis."
                )
            )

        return evidence

    def clean_title(
        self,
    ) -> str:
        """
        Normalize and validate title.
        """

        title = normalize_meaningful_text(
            self.cleaned_data.get(
                "title",
                "",
            )
        )

        if not title:
            raise forms.ValidationError(
                "Analysis title cannot be empty."
            )

        if len(title) < 5:
            raise forms.ValidationError(
                "Analysis title must contain at least 5 characters."
            )

        if not has_meaningful_content(
            title,
            minimum_alphanumeric=4,
        ):
            raise forms.ValidationError(
                "Analysis title must contain meaningful letters or numbers."
            )

        return title


    def clean_custom_prompt(
        self,
    ) -> str:
        """
        Normalize custom prompt text.
        """

        return normalize_meaningful_text(
            self.cleaned_data.get(
                "custom_prompt",
                "",
            )
        )


    def clean(
        self,
    ) -> dict[str, Any]:
        """
        Validate prompt configuration, evidence compatibility and duplicates.
        """

        cleaned_data = super().clean()

        evidence = cleaned_data.get(
            "evidence"
        )

        analysis_type = cleaned_data.get(
            "analysis_type"
        )

        provider = cleaned_data.get(
            "provider"
        )

        prompt_template = cleaned_data.get(
            "prompt_template"
        )

        custom_prompt = cleaned_data.get(
            "custom_prompt",
            "",
        )

        prompt_version = cleaned_data.get(
            "prompt_version"
        )

        use_cached_result = cleaned_data.get(
            "use_cached_result",
            False,
        )

        force_reanalysis = cleaned_data.get(
            "force_reanalysis",
            False,
        )

        configured_model_name = ""

        if provider not in {
            AIAnalysis.Provider.LOCAL,
            AIAnalysis.Provider.GEMINI,
            AIAnalysis.Provider.OPENROUTER,
        }:
            self.add_error(
                "provider",
                "Select Local AI, Google Gemini, or OpenRouter.",
            )
        elif provider == AIAnalysis.Provider.LOCAL:
            configured_model_name = get_configured_model_name(
                provider
            )
        else:
            required_key_setting = (
                "GEMINI_API_KEY"
                if provider == AIAnalysis.Provider.GEMINI
                else "OPENROUTER_API_KEY"
            )

            if not str(
                getattr(settings, required_key_setting, "")
                or ""
            ).strip():
                self.add_error(
                    "provider",
                    (
                        f"{dict(AIAnalysis.Provider.choices)[provider]} "
                        "is not configured on this server."
                    ),
                )

            try:
                configured_model_name = get_configured_model_name(
                    provider
                )
            except AIConfigurationError as exc:
                self.add_error(
                    "provider",
                    str(exc),
                )

        if prompt_template == PROMPT_CUSTOM:
            if len(custom_prompt) < 20:
                self.add_error(
                    "custom_prompt",
                    (
                        "Custom prompt must contain at least 20 characters."
                    ),
                )

            elif not has_meaningful_content(
                custom_prompt,
                minimum_alphanumeric=12,
            ):
                self.add_error(
                    "custom_prompt",
                    (
                        "Custom prompt must contain meaningful forensic "
                        "instructions, not only symbols or punctuation."
                    ),
                )

        if (
            prompt_template != PROMPT_CUSTOM
            and custom_prompt
        ):
            self.add_error(
                "custom_prompt",
                (
                    "Custom prompt should only be supplied when "
                    "Custom Prompt is selected."
                ),
            )

        if (
            use_cached_result
            and force_reanalysis
        ):
            self.add_error(
                "force_reanalysis",
                (
                    "Disable cached-result reuse before forcing a new analysis."
                ),
            )

        if (
            evidence
            and analysis_type
            and not analysis_type_matches_evidence(
                analysis_type,
                evidence,
            )
        ):
            self.add_error(
                "analysis_type",
                (
                    "The selected analysis type does not match the evidence "
                    f"category '{evidence.get_evidence_type_display()}'."
                ),
            )

        if evidence and analysis_type and prompt_version and provider:
            duplicate_queryset = AIAnalysis.objects.filter(
                evidence=evidence,
                analysis_type=analysis_type,
                prompt_version=prompt_version,
                provider=provider,
                is_active=True,
                status__in={
                    AIAnalysis.Status.PENDING,
                    AIAnalysis.Status.QUEUED,
                    AIAnalysis.Status.PROCESSING,
                },
            )

            if duplicate_queryset.exists():
                self.add_error(
                    "analysis_type",
                    (
                        "An active analysis of this type is already pending, "
                        "queued or processing for the selected evidence."
                    ),
                )

            if not force_reanalysis and configured_model_name:
                request_prompt = (
                    custom_prompt
                    if prompt_template == PROMPT_CUSTOM
                    else prompt_template
                )

                expected_cache_key = build_cache_key_from_values(
                    evidence_hash=evidence.sha256_hash,
                    analysis_type=analysis_type,
                    prompt_version=prompt_version,
                    request_prompt=request_prompt,
                    provider=provider,
                    model_name=configured_model_name,
                )

                completed_match = AIAnalysis.objects.filter(
                    evidence=evidence,
                    analysis_type=analysis_type,
                    prompt_version=prompt_version,
                    provider=provider,
                    model_name=configured_model_name,
                    evidence_hash_at_analysis=evidence.sha256_hash,
                    cache_key=expected_cache_key,
                    is_active=True,
                    status=AIAnalysis.Status.COMPLETED,
                ).exists()

                if completed_match and not use_cached_result:
                    self.add_error(
                        "use_cached_result",
                        (
                            "A compatible completed result already exists. "
                            "Enable cached-result reuse or force re-analysis."
                        ),
                    )

        return cleaned_data

    def save(
        self,
        commit: bool = True,
    ) -> AIAnalysis:
        """
        Build an AI analysis request without calling the provider.
        """

        analysis = super().save(
            commit=False
        )

        if self.current_user is None:
            raise ValueError(
                "AIAnalysisRunForm requires current_user."
            )

        prompt_template = self.cleaned_data[
            "prompt_template"
        ]

        custom_prompt = self.cleaned_data.get(
            "custom_prompt",
            "",
        )

        analysis.created_by = self.current_user
        analysis.provider = self.cleaned_data["provider"]
        analysis.model_name = get_configured_model_name(
            analysis.provider
        )
        analysis.prompt_version = self.cleaned_data[
            "prompt_version"
        ]

        analysis.request_prompt = (
            custom_prompt
            if prompt_template == PROMPT_CUSTOM
            else prompt_template
        )

        analysis.evidence_hash_at_analysis = (
            analysis.evidence.sha256_hash
            or ""
        )

        analysis.cache_key = build_cache_key_from_values(
            evidence_hash=analysis.evidence_hash_at_analysis,
            analysis_type=analysis.analysis_type,
            prompt_version=analysis.prompt_version,
            request_prompt=analysis.request_prompt,
            provider=analysis.provider,
            model_name=analysis.model_name,
        )

        analysis.status = AIAnalysis.Status.PENDING
        analysis.cache_status = (
            AIAnalysis.CacheStatus.NOT_CACHED
        )

        if commit:
            analysis.save()
            self.save_m2m()

        return analysis


# ==========================================================
# AI Analysis Filter Form
# ==========================================================

class AIAnalysisFilterForm(forms.Form):
    """
    Search and filter form for the AI analysis list page.
    """

    search = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": (
                    "Search analysis number, title, evidence or case"
                ),
                "autocomplete": "off",
            }
        ),
    )

    case = forms.ModelChoiceField(
        required=False,
        label="Related Case",
        queryset=Case.objects.none(),
        empty_label="All Cases",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    evidence = forms.ModelChoiceField(
        required=False,
        label="Related Evidence",
        queryset=Evidence.objects.none(),
        empty_label="All Evidence",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    analysis_type = forms.ChoiceField(
        required=False,
        label="Analysis Type",
        choices=[
            (
                "",
                "All Analysis Types",
            ),
            *AIAnalysis.AnalysisType.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    status = forms.ChoiceField(
        required=False,
        label="Status",
        choices=[
            (
                "",
                "All Statuses",
            ),
            *AIAnalysis.Status.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    priority = forms.ChoiceField(
        required=False,
        label="Priority",
        choices=[
            (
                "",
                "All Priorities",
            ),
            *AIAnalysis.Priority.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    threat_level = forms.ChoiceField(
        required=False,
        label="Threat Level",
        choices=[
            (
                "",
                "All Threat Levels",
            ),
            *AIAnalysis.ThreatLevel.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    provider = forms.ChoiceField(
        required=False,
        label="Provider",
        choices=[
            (
                "",
                "All Providers",
            ),
            *AIAnalysis.Provider.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    created_by = forms.ModelChoiceField(
        required=False,
        label="Created By",
        queryset=User.objects.none(),
        empty_label="All Creators",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    date_from = forms.DateField(
        required=False,
        label="Created From",
        widget=forms.DateInput(
            attrs={
                "class": "form-control",
                "type": "date",
            }
        ),
    )

    date_to = forms.DateField(
        required=False,
        label="Created To",
        widget=forms.DateInput(
            attrs={
                "class": "form-control",
                "type": "date",
            }
        ),
    )

    minimum_confidence = forms.DecimalField(
        required=False,
        label="Minimum Confidence",
        min_value=0,
        max_value=100,
        decimal_places=2,
        widget=forms.NumberInput(
            attrs={
                "class": "form-control",
                "placeholder": "0",
                "step": "0.01",
            }
        ),
    )

    minimum_risk = forms.DecimalField(
        required=False,
        label="Minimum Risk",
        min_value=0,
        max_value=100,
        decimal_places=2,
        widget=forms.NumberInput(
            attrs={
                "class": "form-control",
                "placeholder": "0",
                "step": "0.01",
            }
        ),
    )

    cache_state = forms.ChoiceField(
        required=False,
        label="Cache State",
        choices=[
            (
                "",
                "All Cache States",
            ),
            (
                "cached",
                "Cached Results",
            ),
            (
                "fresh",
                "Fresh Results",
            ),
            (
                "stale",
                "Stale Results",
            ),
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    active_state = forms.ChoiceField(
        required=False,
        label="Record State",
        choices=[
            (
                "",
                "All Records",
            ),
            (
                "active",
                "Active Analyses",
            ),
            (
                "inactive",
                "Archived Analyses",
            ),
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    ordering = forms.ChoiceField(
        required=False,
        label="Sort By",
        choices=[
            (
                "-created_date",
                "Newest First",
            ),
            (
                "created_date",
                "Oldest First",
            ),
            (
                "title",
                "Title A-Z",
            ),
            (
                "-title",
                "Title Z-A",
            ),
            (
                "-risk_score",
                "Highest Risk First",
            ),
            (
                "-confidence_score",
                "Highest Confidence First",
            ),
            (
                "status",
                "Status",
            ),
            (
                "priority",
                "Priority",
            ),
        ],
        initial="-created_date",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    def __init__(
        self,
        *args: Any,
        current_user: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Load role-accessible cases, evidence and creators.
        """

        super().__init__(
            *args,
            **kwargs,
        )

        self.fields[
            "case"
        ].queryset = get_accessible_case_queryset(
            current_user
        )

        self.fields[
            "evidence"
        ].queryset = get_accessible_evidence_queryset(
            current_user
        )

        self.fields[
            "created_by"
        ].queryset = get_active_user_queryset()

    def clean(
        self,
    ) -> dict[str, Any]:
        """
        Validate date range and numeric filters.
        """

        cleaned_data = super().clean()

        date_from = cleaned_data.get(
            "date_from"
        )

        date_to = cleaned_data.get(
            "date_to"
        )

        if (
            date_from
            and date_to
            and date_from > date_to
        ):
            self.add_error(
                "date_to",
                (
                    "End date must be on or after the start date."
                ),
            )

        today = date.today()

        if date_to and date_to > today:
            self.add_error(
                "date_to",
                "End date cannot be in the future.",
            )

        return cleaned_data


# ==========================================================
# AI Analysis Review Form
# ==========================================================

class AIAnalysisReviewForm(forms.ModelForm):
    """
    Record human review notes for a completed or failed AI analysis.
    """

    class Meta:
        model = AIAnalysis

        fields = [
            "review_notes",
        ]

        labels = {
            "review_notes": "Review Notes",
        }

        help_texts = {
            "review_notes": (
                "Record whether the AI output is useful, accurate and "
                "appropriate for the investigation."
            ),
        }

        widgets = {
            "review_notes": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 7,
                    "maxlength": "5000",
                    "placeholder": (
                        "Enter human review observations and limitations"
                    ),
                }
            ),
        }

    def __init__(
        self,
        *args: Any,
        current_user: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            *args,
            **kwargs,
        )

        self.current_user = current_user

    def clean_review_notes(
        self,
    ) -> str:
        """
        Normalize and validate review notes.
        """

        review_notes = normalize_meaningful_text(
            self.cleaned_data.get(
                "review_notes",
                "",
            )
        )

        if len(review_notes) < 10:
            raise forms.ValidationError(
                "Review notes must contain at least 10 characters."
            )

        if not has_meaningful_content(
            review_notes,
            minimum_alphanumeric=8,
        ):
            raise forms.ValidationError(
                "Review notes must contain meaningful letters or numbers."
            )

        return review_notes


    def save(
        self,
        commit: bool = True,
    ) -> AIAnalysis:
        """
        Save reviewer information.
        """

        analysis = super().save(
            commit=False
        )

        if self.current_user is None:
            raise ValueError(
                "AIAnalysisReviewForm requires current_user."
            )

        from django.utils import timezone

        analysis.reviewed_by = self.current_user
        analysis.reviewed_at = timezone.now()

        if commit:
            analysis.save()
            self.save_m2m()

        return analysis


# ==========================================================
# AI Analysis Archive Form
# ==========================================================

class AIAnalysisArchiveForm(forms.Form):
    """
    Confirmation form for archiving an AI analysis.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this AI analysis should be archived."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    reason = forms.CharField(
        required=False,
        label="Archive Reason",
        max_length=1000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 5,
                "maxlength": "1000",
                "placeholder": (
                    "Explain why this analysis is being archived"
                ),
            }
        ),
    )

    def clean_reason(
        self,
    ) -> str:
        """
        Normalize and validate an optional archive reason.
        """

        reason = normalize_meaningful_text(
            self.cleaned_data.get(
                "reason",
                "",
            )
        )

        if reason and len(reason) < 10:
            raise forms.ValidationError(
                (
                    "Archive reason must contain at least "
                    "10 characters when provided."
                )
            )

        if reason and not has_meaningful_content(
            reason,
            minimum_alphanumeric=8,
        ):
            raise forms.ValidationError(
                "Archive reason must contain meaningful letters or numbers."
            )

        return reason


# ==========================================================
# AI Analysis Cancel Form
# ==========================================================

class AIAnalysisCancelForm(forms.Form):
    """
    Confirmation form for cancelling a pending or queued analysis.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this pending analysis should be cancelled."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    cancellation_reason = forms.CharField(
        required=True,
        label="Cancellation Reason",
        min_length=10,
        max_length=1000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 5,
                "maxlength": "1000",
                "placeholder": (
                    "Enter the reason for cancelling this analysis"
                ),
            }
        ),
    )

    def clean_cancellation_reason(
        self,
    ) -> str:
        """
        Require a meaningful cancellation reason.
        """

        cancellation_reason = normalize_meaningful_text(
            self.cleaned_data.get(
                "cancellation_reason",
                "",
            )
        )

        if len(cancellation_reason) < 10:
            raise forms.ValidationError(
                (
                    "Cancellation reason must contain at least "
                    "10 characters."
                )
            )

        if not has_meaningful_content(
            cancellation_reason,
            minimum_alphanumeric=8,
        ):
            raise forms.ValidationError(
                (
                    "Cancellation reason must contain meaningful "
                    "letters or numbers."
                )
            )

        return cancellation_reason
