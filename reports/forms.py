"""
AIDEX Reports Forms

Professional, role-aware forms for:

- Creating and editing investigation reports
- Filtering/searching reports
- Submitting reports for review
- Reviewing / approving / rejecting reports
- Publishing approved reports
- Creating report revisions
- Archiving and restoring reports

These forms are intentionally workflow-aware. They do not expose arbitrary
status changes or lifecycle flags such as is_active directly to normal users.
"""

from __future__ import annotations

from typing import Any

from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q, QuerySet

from ai_engine.models import AIAnalysis
from cases.models import Case
from evidence.models import Evidence

from .models import (
    MAX_REPORT_FILE_SIZE,
    Report,
    validate_report_file_signature,
)


User = get_user_model()


# ============================================================================
# Role Configuration
# ============================================================================

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


# ============================================================================
# Generic Helpers
# ============================================================================

def normalize_role(
    role_value: Any,
) -> str:
    """
    Convert different role representations into standard AIDEX values.
    """

    normalized = (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return ROLE_ALIASES.get(
        normalized,
        normalized,
    )


def get_user_role(
    user: Any,
) -> str:
    """
    Return the normalized AIDEX role for one user.
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


def user_has_role(
    user: Any,
    *roles: str,
) -> bool:
    """
    Return True when user belongs to any supplied AIDEX role.
    """

    current_role = get_user_role(
        user
    )

    normalized_roles = {
        normalize_role(role)
        for role in roles
    }

    return current_role in normalized_roles


def normalize_text(
    value: Any,
) -> str:
    """
    Trim surrounding whitespace while preserving meaningful line breaks.
    """

    text = (
        str(value or "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    return "\n".join(
        line.rstrip()
        for line in text.splitlines()
    ).strip()


# ============================================================================
# Accessible Querysets
# ============================================================================

def get_accessible_case_queryset(
    user: Any,
    *,
    include_case: Case | None = None,
) -> QuerySet[Case]:
    """
    Return cases the current user may use for report creation/editing.
    """

    queryset = Case.objects.select_related(
        "created_by",
        "assigned_investigator",
    )

    if not getattr(
        user,
        "is_authenticated",
        False,
    ):
        return queryset.none()

    active_filter = (
        Q(is_active=True)
        & ~Q(
            status=Case.Status.ARCHIVED
        )
    )

    role = get_user_role(
        user
    )

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        access_filter = active_filter

    elif role == ROLE_INVESTIGATOR:
        access_filter = (
            active_filter
            & (
                Q(created_by=user)
                | Q(
                    assigned_investigator=user
                )
            )
        )

    else:
        return queryset.none()

    if include_case is not None:
        access_filter = (
            access_filter
            | Q(pk=include_case.pk)
        )

    return (
        queryset
        .filter(
            access_filter
        )
        .distinct()
        .order_by(
            "-created_date"
        )
    )


def get_report_evidence_queryset(
    user: Any,
    *,
    case: Case | None = None,
) -> QuerySet[Evidence]:
    """
    Return active evidence that may be attached to a report.
    """

    queryset = Evidence.objects.select_related(
        "case",
        "uploaded_by",
        "verified_by",
    ).filter(
        is_active=True
    )

    if case is not None:
        queryset = queryset.filter(
            case=case
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

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        return queryset.order_by(
            "-uploaded_date"
        )

    if role == ROLE_INVESTIGATOR:
        return (
            queryset
            .filter(
                Q(case__created_by=user)
                | Q(
                    case__assigned_investigator=user
                )
                | Q(uploaded_by=user)
            )
            .distinct()
            .order_by(
                "-uploaded_date"
            )
        )

    return queryset.none()


def get_report_analysis_queryset(
    user: Any,
    *,
    case: Case | None = None,
) -> QuerySet[AIAnalysis]:
    """
    Return active, completed and human-reviewed AI analyses suitable for
    official report inclusion.

    A completed Gemini result is not treated as report-ready until an
    authorized human reviewer has recorded both reviewed_by and reviewed_at.
    """

    queryset = (
        AIAnalysis.objects
        .select_related(
            "evidence",
            "evidence__case",
            "created_by",
        )
        .filter(
            is_active=True,
            status=AIAnalysis.Status.COMPLETED,
            evidence__is_active=True,
            reviewed_by__isnull=False,
            reviewed_at__isnull=False,
        )
    )

    if case is not None:
        queryset = queryset.filter(
            evidence__case=case
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

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        return queryset.order_by(
            "-completed_at",
            "-created_date",
        )

    if role == ROLE_INVESTIGATOR:
        return (
            queryset
            .filter(
                Q(
                    evidence__case__created_by=user
                )
                | Q(
                    evidence__case__assigned_investigator=user
                )
                | Q(created_by=user)
            )
            .distinct()
            .order_by(
                "-completed_at",
                "-created_date",
            )
        )

    return queryset.none()


def get_active_user_queryset() -> QuerySet:
    """
    Return active AIDEX users for report filters.
    """

    queryset = User.objects.filter(
        is_active=True
    )

    account_status_model = getattr(
        User,
        "AccountStatus",
        None,
    )

    if account_status_model is not None:
        queryset = queryset.filter(
            account_status=(
                account_status_model.ACTIVE
            )
        )

    return queryset.order_by(
        "full_name",
        "username",
    )


# ============================================================================
# Main Create / Edit Form
# ============================================================================

class ReportForm(forms.ModelForm):
    """
    Create or edit report content.

    Status is intentionally excluded. Workflow state changes must use the
    dedicated submit/review/approve/reject/publish/archive/restore forms.
    """

    included_evidence = forms.ModelMultipleChoiceField(
        required=False,
        queryset=Evidence.objects.none(),
        label="Included Evidence",
        help_text=(
            "Select evidence records explicitly referenced by this report."
        ),
        widget=forms.SelectMultiple(
            attrs={
                "class": "form-select",
                "size": "8",
            }
        ),
    )

    included_analyses = forms.ModelMultipleChoiceField(
        required=False,
        queryset=AIAnalysis.objects.none(),
        label="Included AI Analyses",
        help_text=(
            "Select completed, human-reviewed AI analyses explicitly "
            "referenced by this report."
        ),
        widget=forms.SelectMultiple(
            attrs={
                "class": "form-select",
                "size": "8",
            }
        ),
    )

    class Meta:
        model = Report

        fields = [
            "case",
            "report_title",
            "report_type",
            "summary",
            "findings",
            "evidence_summary",
            "ai_analysis_summary",
            "conclusion",
            "recommendations",
            "report_file",
            "included_evidence",
            "included_analyses",
            "is_confidential",
        ]

        labels = {
            "case": "Related Case",
            "report_title": "Report Title",
            "report_type": "Report Type",
            "summary": "Executive Summary",
            "findings": "Investigation Findings",
            "evidence_summary": "Evidence Summary",
            "ai_analysis_summary": "AI Analysis Summary",
            "conclusion": "Conclusion",
            "recommendations": "Recommendations",
            "report_file": "Report File",
            "is_confidential": "Confidential Report",
        }

        help_texts = {
            "case": (
                "Select the cyber-crime case associated with this report."
            ),
            "report_title": (
                "Use a clear, specific and investigation-relevant title."
            ),
            "report_type": (
                "Choose the report category that best represents its purpose."
            ),
            "summary": (
                "Provide a concise overview of scope, context and key outcome."
            ),
            "findings": (
                "Record material findings supported by case evidence."
            ),
            "evidence_summary": (
                "Summarize the evidence used and its relevance."
            ),
            "ai_analysis_summary": (
                "Summarize only human-reviewed AI-assisted findings."
            ),
            "conclusion": (
                "State an evidence-grounded conclusion."
            ),
            "recommendations": (
                "Record practical investigative or procedural next steps."
            ),
            "report_file": (
                "Optional while drafting. PDF, DOC or DOCX; maximum 25 MB. "
                "Published reports must use PDF."
            ),
            "is_confidential": (
                "Confidential reports should only be shown to authorized users."
            ),
        }

        widgets = {
            "case": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "report_title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": (
                        "Enter a descriptive investigation report title"
                    ),
                    "maxlength": "200",
                    "autocomplete": "off",
                }
            ),
            "report_type": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "summary": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 5,
                    "placeholder": (
                        "Summarize the report scope and key investigation outcome"
                    ),
                }
            ),
            "findings": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 8,
                    "placeholder": (
                        "Document evidence-grounded investigation findings"
                    ),
                }
            ),
            "evidence_summary": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 7,
                    "placeholder": (
                        "Summarize the digital evidence referenced in this report"
                    ),
                }
            ),
            "ai_analysis_summary": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 7,
                    "placeholder": (
                        "Summarize reviewed AI-assisted findings and limitations"
                    ),
                }
            ),
            "conclusion": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 6,
                    "placeholder": (
                        "Enter the evidence-grounded investigation conclusion"
                    ),
                }
            ),
            "recommendations": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 6,
                    "placeholder": (
                        "Enter recommended investigative or procedural actions"
                    ),
                }
            ),
            "report_file": forms.ClearableFileInput(
                attrs={
                    "class": "form-control",
                    "accept": ".pdf,.doc,.docx",
                }
            ),
            "is_confidential": forms.CheckboxInput(
                attrs={
                    "class": "form-check-input",
                    "role": "switch",
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

        # UUID primary keys may be generated before the object is saved.
        # Therefore instance.pk alone cannot distinguish Create from Update.
        # Django's model state is the reliable source of truth.
        self.is_update = bool(
            self.instance
            and not self.instance._state.adding
        )

        current_case = (
            self.instance.case
            if self.is_update
            and self.instance.case_id
            else None
        )

        self.fields[
            "case"
        ].queryset = get_accessible_case_queryset(
            current_user,
            include_case=current_case,
        )

        self.fields[
            "case"
        ].empty_label = (
            "Select related case"
        )

        self.fields[
            "report_title"
        ].widget.attrs[
            "autofocus"
        ] = True

        if self.is_update:
            self.fields[
                "report_file"
            ].required = False

        else:
            self.fields[
                "report_type"
            ].initial = (
                Report.ReportType.INVESTIGATION
            )

            self.fields[
                "is_confidential"
            ].initial = True

        selected_case = self._resolve_selected_case()

        self._configure_reference_querysets(
            selected_case
        )

        self._apply_editability_rules()

    def _resolve_selected_case(
        self,
    ) -> Case | None:
        """
        Resolve the best case context for evidence/analysis selector scoping.
        """

        raw_case_id = None

        if self.is_bound:
            raw_case_id = self.data.get(
                self.add_prefix(
                    "case"
                )
            )

        if (
            not raw_case_id
            and self.is_update
            and self.instance.case_id
        ):
            return self.instance.case

        if not raw_case_id:
            initial_case = self.initial.get(
                "case"
            )

            if isinstance(
                initial_case,
                Case,
            ):
                return initial_case

            raw_case_id = initial_case

        if not raw_case_id:
            return None

        return (
            get_accessible_case_queryset(
                self.current_user
            )
            .filter(
                pk=raw_case_id
            )
            .first()
        )

    def _configure_reference_querysets(
        self,
        case: Case | None,
    ) -> None:
        """
        Scope evidence and AI analysis selectors to the chosen case.
        """

        evidence_queryset = (
            get_report_evidence_queryset(
                self.current_user,
                case=case,
            )
        )

        analysis_queryset = (
            get_report_analysis_queryset(
                self.current_user,
                case=case,
            )
        )

        if self.is_update:
            # Preserve already-linked references while editing even when they
            # are no longer part of the normal selectable queryset.
            #
            # Avoid QuerySet `|` here: Django refuses to combine a DISTINCT
            # queryset with a non-DISTINCT queryset ("Cannot combine a unique
            # query with a non-unique query."). Using pk subqueries produces
            # one clean queryset and works consistently on SQLite.
            evidence_queryset = (
                Evidence.objects
                .filter(
                    Q(
                        pk__in=evidence_queryset.values(
                            "pk"
                        )
                    )
                    | Q(
                        pk__in=(
                            self.instance
                            .included_evidence
                            .values("pk")
                        )
                    )
                )
                .distinct()
            )

            analysis_queryset = (
                AIAnalysis.objects
                .filter(
                    Q(
                        pk__in=analysis_queryset.values(
                            "pk"
                        )
                    )
                    | Q(
                        pk__in=(
                            self.instance
                            .included_analyses
                            .values("pk")
                        )
                    )
                )
                .distinct()
            )

        self.fields[
            "included_evidence"
        ].queryset = (
            evidence_queryset
            .distinct()
        )

        self.fields[
            "included_analyses"
        ].queryset = (
            analysis_queryset
            .distinct()
        )

    def _apply_editability_rules(
        self,
    ) -> None:
        """
        Enforce model workflow rules at form level.
        """

        if not self.is_update:
            return

        if not self.instance.can_be_edited:
            for field in self.fields.values():
                field.disabled = True

    def clean_case(
        self,
    ) -> Case:
        case = self.cleaned_data.get(
            "case"
        )

        if case is None:
            raise forms.ValidationError(
                "Please select a related case."
            )

        accessible = (
            get_accessible_case_queryset(
                self.current_user,
                include_case=(
                    self.instance.case
                    if self.is_update
                    and self.instance.case_id
                    else None
                ),
            )
        )

        if not accessible.filter(
            pk=case.pk
        ).exists():
            raise forms.ValidationError(
                "You do not have access to the selected case."
            )

        if (
            not self.is_update
            and (
                not case.is_active
                or case.status
                == Case.Status.ARCHIVED
            )
        ):
            raise forms.ValidationError(
                "Reports cannot be created for an archived or inactive case."
            )

        return case

    def clean_report_title(
        self,
    ) -> str:
        title = normalize_text(
            self.cleaned_data.get(
                "report_title",
                "",
            )
        )

        if len(title) < 5:
            raise forms.ValidationError(
                "Report title must contain at least 5 characters."
            )

        return title

    def clean_report_file(
        self,
    ):
        report_file = self.cleaned_data.get(
            "report_file"
        )

        if not report_file:
            if self.is_update:
                return self.instance.report_file

            return report_file

        try:
            size = int(
                report_file.size
            )
        except (
            TypeError,
            ValueError,
            OSError,
        ) as exc:
            raise forms.ValidationError(
                "The report file size could not be determined."
            ) from exc

        if size <= 0:
            raise forms.ValidationError(
                "Empty report files are not allowed."
            )

        if size > MAX_REPORT_FILE_SIZE:
            raise forms.ValidationError(
                "Report file size cannot exceed 25 MB."
            )

        validate_report_file_signature(
            report_file
        )

        return report_file

    def clean_included_evidence(
        self,
    ):
        selected_evidence = self.cleaned_data.get(
            "included_evidence"
        )

        if not selected_evidence:
            return selected_evidence

        selected_case = self.cleaned_data.get(
            "case"
        )

        if selected_case is None:
            return selected_evidence

        invalid = selected_evidence.exclude(
            case=selected_case,
            is_active=True,
        )

        if invalid.exists():
            raise forms.ValidationError(
                (
                    "All included evidence must be active and belong "
                    "to the selected case."
                )
            )

        return selected_evidence

    def clean_included_analyses(
        self,
    ):
        selected_analyses = self.cleaned_data.get(
            "included_analyses"
        )

        if not selected_analyses:
            return selected_analyses

        selected_case = self.cleaned_data.get(
            "case"
        )

        valid_requirements = {
            "evidence__is_active": True,
            "is_active": True,
            "status": AIAnalysis.Status.COMPLETED,
            "reviewed_by__isnull": False,
            "reviewed_at__isnull": False,
        }

        if selected_case is not None:
            valid_requirements[
                "evidence__case"
            ] = selected_case

        invalid = selected_analyses.exclude(
            **valid_requirements
        )

        if invalid.exists():
            raise forms.ValidationError(
                (
                    "All included AI analyses must be active, completed, "
                    "human-reviewed, and belong to evidence from the "
                    "selected case."
                )
            )

        return selected_analyses

    def clean(
        self,
    ) -> dict[str, Any]:
        cleaned_data = super().clean()

        if (
            self.is_update
            and not self.instance.can_be_edited
        ):
            raise forms.ValidationError(
                (
                    "This report version cannot be edited in its current "
                    "workflow state. Create a revision or use the appropriate "
                    "review workflow."
                )
            )

        case = cleaned_data.get(
            "case"
        )

        title = cleaned_data.get(
            "report_title"
        )

        report_type = cleaned_data.get(
            "report_type"
        )

        if (
            case
            and title
            and report_type
        ):
            duplicate_queryset = (
                Report.objects
                .filter(
                    case=case,
                    report_title__iexact=title,
                    report_type=report_type,
                    version=(
                        self.instance.version
                        if self.is_update
                        else 1
                    ),
                )
            )

            if self.is_update:
                duplicate_queryset = (
                    duplicate_queryset.exclude(
                        pk=self.instance.pk
                    )
                )

            if duplicate_queryset.exists():
                self.add_error(
                    "report_title",
                    (
                        "A report with this title, type and version "
                        "already exists for the selected case."
                    ),
                )

        return cleaned_data

    def save(
        self,
        commit: bool = True,
    ) -> Report:
        report = super().save(
            commit=False
        )

        if report._state.adding:
            if self.current_user is None:
                raise ValueError(
                    (
                        "ReportForm requires current_user when "
                        "creating a report."
                    )
                )

            report.generated_by = (
                self.current_user
            )
            report.status = (
                Report.Status.DRAFT
            )
            report.is_active = True

        if commit:
            report.save()
            self.save_m2m()

        return report


# ============================================================================
# Filtering / Search
# ============================================================================

class ReportFilterForm(forms.Form):
    """
    Search/filter form for the report listing page.
    """

    search = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": (
                    "Search by report number, title, case number or summary"
                ),
                "autocomplete": "off",
            }
        ),
    )

    case = forms.ModelChoiceField(
        required=False,
        queryset=Case.objects.none(),
        empty_label="All Cases",
        label="Case",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    report_type = forms.ChoiceField(
        required=False,
        label="Report Type",
        choices=[
            (
                "",
                "All Report Types",
            ),
            *Report.ReportType.choices,
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
            *Report.Status.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    generated_by = forms.ModelChoiceField(
        required=False,
        queryset=User.objects.none(),
        empty_label="All Authors",
        label="Generated By",
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    confidentiality = forms.ChoiceField(
        required=False,
        label="Confidentiality",
        choices=[
            (
                "",
                "All Reports",
            ),
            (
                "confidential",
                "Confidential",
            ),
            (
                "standard",
                "Non-confidential",
            ),
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    record_state = forms.ChoiceField(
        required=False,
        label="Record State",
        choices=[
            (
                "",
                "All Records",
            ),
            (
                "active",
                "Active Reports",
            ),
            (
                "archived",
                "Archived Reports",
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
        initial="-generated_date",
        choices=[
            (
                "-generated_date",
                "Newest First",
            ),
            (
                "generated_date",
                "Oldest First",
            ),
            (
                "report_title",
                "Title A-Z",
            ),
            (
                "-report_title",
                "Title Z-A",
            ),
            (
                "status",
                "Status",
            ),
            (
                "report_type",
                "Report Type",
            ),
            (
                "-updated_date",
                "Recently Updated",
            ),
        ],
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
        super().__init__(
            *args,
            **kwargs,
        )

        self.fields[
            "case"
        ].queryset = (
            get_accessible_case_queryset(
                current_user
            )
        )

        self.fields[
            "generated_by"
        ].queryset = (
            get_active_user_queryset()
        )


# ============================================================================
# Workflow Forms
# ============================================================================

class ReportSubmitForReviewForm(forms.Form):
    """
    Confirm submission of a Draft/Rejected report for formal review.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this report is ready for formal review."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    submission_note = forms.CharField(
        required=False,
        max_length=1500,
        label="Submission Note",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 4,
                "maxlength": "1500",
                "placeholder": (
                    "Optional note for the reviewer"
                ),
            }
        ),
    )

    def clean_submission_note(
        self,
    ) -> str:
        return normalize_text(
            self.cleaned_data.get(
                "submission_note",
                "",
            )
        )


class ReportReviewForm(forms.Form):
    """
    Record reviewer observations while a report is Under Review.

    This form does not itself approve/reject the report; those decisions use
    dedicated forms so final actions remain explicit.
    """

    review_notes = forms.CharField(
        required=True,
        min_length=10,
        max_length=4000,
        label="Review Notes",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 7,
                "maxlength": "4000",
                "placeholder": (
                    "Document review observations, corrections and limitations"
                ),
            }
        ),
    )

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that these review notes accurately reflect my review."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    def clean_review_notes(
        self,
    ) -> str:
        notes = normalize_text(
            self.cleaned_data.get(
                "review_notes",
                "",
            )
        )

        if sum(
            character.isalnum()
            for character in notes
        ) < 8:
            raise forms.ValidationError(
                "Enter meaningful review observations."
            )

        return notes


class ReportApproveForm(forms.Form):
    """
    Explicit approval decision for an Under Review report.
    """

    approval_notes = forms.CharField(
        required=False,
        max_length=3000,
        label="Approval Notes",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 5,
                "maxlength": "3000",
                "placeholder": (
                    "Optional approval notes or conditions"
                ),
            }
        ),
    )

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that I have reviewed this report and approve it."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    def clean_approval_notes(
        self,
    ) -> str:
        return normalize_text(
            self.cleaned_data.get(
                "approval_notes",
                "",
            )
        )


class ReportRejectForm(forms.Form):
    """
    Explicit rejection decision for an Under Review report.
    """

    rejection_reason = forms.CharField(
        required=True,
        min_length=10,
        max_length=4000,
        label="Rejection Reason",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 6,
                "maxlength": "4000",
                "placeholder": (
                    "Explain why the report is being rejected and "
                    "what requires correction"
                ),
            }
        ),
    )

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this report should be rejected for revision."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    def clean_rejection_reason(
        self,
    ) -> str:
        reason = normalize_text(
            self.cleaned_data.get(
                "rejection_reason",
                "",
            )
        )

        if sum(
            character.isalnum()
            for character in reason
        ) < 8:
            raise forms.ValidationError(
                "Enter a meaningful rejection reason."
            )

        return reason


class ReportPublishForm(forms.Form):
    """
    Confirm publication of an Approved report.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this approved report is ready for publication."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    publication_note = forms.CharField(
        required=False,
        max_length=2000,
        label="Publication Note",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 4,
                "maxlength": "2000",
                "placeholder": (
                    "Optional publication note"
                ),
            }
        ),
    )

    def clean_publication_note(
        self,
    ) -> str:
        return normalize_text(
            self.cleaned_data.get(
                "publication_note",
                "",
            )
        )


class ReportArchiveForm(forms.Form):
    """
    Confirmation form for report archiving.
    """

    reason = forms.CharField(
        required=True,
        min_length=10,
        max_length=1000,
        label="Archive Reason",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 4,
                "maxlength": "1000",
                "placeholder": (
                    "Enter the reason for archiving this report"
                ),
            }
        ),
    )

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this report should be archived."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    def clean_reason(
        self,
    ) -> str:
        reason = normalize_text(
            self.cleaned_data.get(
                "reason",
                "",
            )
        )

        if sum(
            character.isalnum()
            for character in reason
        ) < 8:
            raise forms.ValidationError(
                (
                    "Enter a meaningful archive reason containing "
                    "at least 8 letters or numbers."
                )
            )

        return reason


class ReportRestoreForm(forms.Form):
    """
    Confirmation form for restoring an archived report.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this archived report should be restored."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )


# ============================================================================
# Revision Form
# ============================================================================

class ReportRevisionForm(forms.Form):
    """
    Create a new draft revision from an existing report.

    The actual cloning should be performed transactionally in services/views.
    """

    revision_title = forms.CharField(
        required=False,
        max_length=200,
        label="Revision Title",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "maxlength": "200",
                "placeholder": (
                    "Optional new title; leave blank to keep the current title"
                ),
            }
        ),
    )

    revision_reason = forms.CharField(
        required=True,
        min_length=10,
        max_length=2000,
        label="Revision Reason",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 5,
                "maxlength": "2000",
                "placeholder": (
                    "Explain why a new report revision is required"
                ),
            }
        ),
    )

    copy_report_file = forms.BooleanField(
        required=False,
        initial=False,
        label=(
            "Copy the existing report file into the new revision"
        ),
        help_text=(
            "Usually leave this unchecked so the new revision receives "
            "a newly generated final file."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    def clean_revision_title(
        self,
    ) -> str:
        title = normalize_text(
            self.cleaned_data.get(
                "revision_title",
                "",
            )
        )

        if title and len(title) < 5:
            raise forms.ValidationError(
                "Revision title must contain at least 5 characters."
            )

        return title

    def clean_revision_reason(
        self,
    ) -> str:
        reason = normalize_text(
            self.cleaned_data.get(
                "revision_reason",
                "",
            )
        )

        if sum(
            character.isalnum()
            for character in reason
        ) < 8:
            raise forms.ValidationError(
                "Enter a meaningful revision reason."
            )

        return reason
