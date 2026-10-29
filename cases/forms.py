"""
AIDEX Case Forms

Provides secure and validated forms for:

- Creating cyber-crime cases
- Updating existing cases
- Assigning active investigators
- Filtering and searching cases
"""

from __future__ import annotations

from django import forms
from django.contrib.auth import get_user_model

from .models import Case


User = get_user_model()


# ==========================================================
# Case Status Workflow
# ==========================================================

CASE_STATUS_TRANSITIONS = {
    Case.Status.OPEN: (
        Case.Status.ASSIGNED,
    ),
    Case.Status.ASSIGNED: (
        Case.Status.UNDER_INVESTIGATION,
    ),
    Case.Status.UNDER_INVESTIGATION: (
        Case.Status.ASSIGNED,
        Case.Status.EVIDENCE_COLLECTION,
    ),
    Case.Status.EVIDENCE_COLLECTION: (
        Case.Status.UNDER_INVESTIGATION,
        Case.Status.AI_ANALYSIS,
    ),
    Case.Status.AI_ANALYSIS: (
        Case.Status.EVIDENCE_COLLECTION,
        Case.Status.REPORT_GENERATION,
    ),
    Case.Status.REPORT_GENERATION: (
        Case.Status.AI_ANALYSIS,
        Case.Status.CLOSED,
    ),
    Case.Status.CLOSED: (
        Case.Status.REPORT_GENERATION,
    ),
    Case.Status.ARCHIVED: (),
}


def _is_privileged_case_manager(user) -> bool:
    """
    Return True for administrators and cyber officers.

    Superusers are treated as administrators.
    """

    if user is None:
        return False

    if getattr(user, "is_superuser", False):
        return True

    return getattr(
        user,
        "role",
        "",
    ) in {
        User.Role.ADMINISTRATOR,
        User.Role.CYBER_OFFICER,
    }


def get_allowed_case_statuses(
    case: Case,
    current_user=None,
) -> tuple[str, ...]:
    """
    Return workflow states that may follow the case's current status.

    Rules:
    - ARCHIVED is never changed here; use Restore Case.
    - CLOSED may only be reopened by an Administrator/Cyber Officer.
    - A case cannot enter ASSIGNED or a later investigation state until an
      investigator is assigned.
    """

    if not case or not case.pk:
        return ()

    current_status = case.status

    if current_status == Case.Status.ARCHIVED:
        return ()

    allowed = list(
        CASE_STATUS_TRANSITIONS.get(
            current_status,
            (),
        )
    )

    if (
        current_status == Case.Status.CLOSED
        and not _is_privileged_case_manager(current_user)
    ):
        return ()

    if case.assigned_investigator_id is None:
        allowed = [
            status
            for status in allowed
            if status not in {
                Case.Status.ASSIGNED,
                Case.Status.UNDER_INVESTIGATION,
                Case.Status.EVIDENCE_COLLECTION,
                Case.Status.AI_ANALYSIS,
                Case.Status.REPORT_GENERATION,
            }
        ]

    return tuple(allowed)


class CaseForm(forms.ModelForm):
    """
    Create and update AIDEX cyber-crime cases.

    The form limits investigator assignment to active users
    whose role is Investigator.
    """

    class Meta:
        model = Case

        fields = [
            "case_title",
            "description",
            "crime_category",
            "priority",
            "status",
            "assigned_investigator",
        ]

        labels = {
            "case_title": "Case Title",
            "description": "Case Description",
            "crime_category": "Crime Category",
            "priority": "Priority Level",
            "status": "Case Status",
            "assigned_investigator": "Assigned Investigator",
        }

        help_texts = {
            "case_title": (
                "Enter a clear and descriptive title for the case."
            ),
            "description": (
                "Provide complete details about the cyber-crime incident."
            ),
            "assigned_investigator": (
                "Only active investigators can be assigned."
            ),
        }

        widgets = {
            "case_title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Enter case title",
                    "autocomplete": "off",
                    "maxlength": "200",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "placeholder": (
                        "Enter complete cyber-crime case details"
                    ),
                    "rows": 7,
                }
            ),
            "crime_category": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "priority": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "status": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "assigned_investigator": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }

    def __init__(
        self,
        *args,
        current_user=None,
        **kwargs,
    ):
        """
        Configure investigator choices and role-based fields.
        """

        super().__init__(*args, **kwargs)

        self.current_user = current_user

        # UUID primary keys are generated before the object is saved, so
        # instance.pk cannot distinguish Create from Update reliably.
        self.is_update = bool(
            self.instance
            and not self.instance._state.adding
        )

        self.fields[
            "assigned_investigator"
        ].queryset = (
            User.objects
            .filter(
                role=User.Role.INVESTIGATOR,
                account_status=User.AccountStatus.ACTIVE,
                is_active=True,
            )
            .order_by(
                "full_name",
                "username",
            )
        )

        self.fields[
            "assigned_investigator"
        ].empty_label = "Select investigator"

        self.fields[
            "case_title"
        ].widget.attrs.update({
            "autofocus": True,
        })

        # Normal status changes are handled by CaseStatusForm.
        # During creation, a case starts Open. During metadata editing, the
        # current status is displayed but cannot be modified through this form.
        if not self.is_update:
            self.fields["status"].choices = [
                (
                    Case.Status.OPEN,
                    Case.Status.OPEN.label,
                ),
            ]

            self.fields[
                "status"
            ].initial = Case.Status.OPEN

            self.fields[
                "priority"
            ].initial = Case.Priority.MEDIUM

            self.fields[
                "crime_category"
            ].initial = Case.CrimeCategory.OTHER

        else:
            current_status = self.instance.status

            self.fields["status"].choices = [
                (
                    current_status,
                    self.instance.get_status_display(),
                ),
            ]

            self.fields["status"].disabled = True

            self.fields["status"].help_text = (
                "Use the dedicated Update Status action on the case "
                "detail page to change workflow state."
            )

        self._apply_role_permissions()

    def _apply_role_permissions(self):
        """
        Restrict sensitive fields based on the current user's role.
        """

        if self.current_user is None:
            return

        if getattr(
            self.current_user,
            "is_superuser",
            False,
        ):
            return

        user_role = getattr(
            self.current_user,
            "role",
            "",
        )

        if user_role == User.Role.INVESTIGATOR:
            self.fields.pop(
                "assigned_investigator",
                None,
            )

        elif user_role == User.Role.CYBER_OFFICER:
            self.fields.pop(
                "assigned_investigator",
                None,
            )

    def clean_case_title(self) -> str:
        """
        Normalize and validate the case title.
        """

        case_title = (
            self.cleaned_data
            .get(
                "case_title",
                "",
            )
            .strip()
        )

        if not case_title:
            raise forms.ValidationError(
                "Case title cannot be empty."
            )

        if len(case_title) < 5:
            raise forms.ValidationError(
                "Case title must contain at least 5 characters."
            )

        duplicate_cases = Case.objects.filter(
            case_title__iexact=case_title,
            is_active=True,
        )

        if self.is_update:
            duplicate_cases = duplicate_cases.exclude(
                pk=self.instance.pk
            )

        if duplicate_cases.exists():
            raise forms.ValidationError(
                (
                    "An active case with the same title already exists. "
                    "Please use a more specific title."
                )
            )

        return case_title

    def clean_description(self) -> str:
        """
        Normalize and validate the case description.
        """

        description = (
            self.cleaned_data
            .get(
                "description",
                "",
            )
            .strip()
        )

        if not description:
            raise forms.ValidationError(
                "Case description cannot be empty."
            )

        if len(description) < 20:
            raise forms.ValidationError(
                (
                    "Case description must contain at least "
                    "20 characters."
                )
            )

        return description

    def clean_assigned_investigator(self):
        """
        Validate the selected investigator.
        """

        investigator = self.cleaned_data.get(
            "assigned_investigator"
        )

        if investigator is None:
            return None

        if investigator.role != User.Role.INVESTIGATOR:
            raise forms.ValidationError(
                "Only users with the Investigator role can be assigned."
            )

        if not investigator.is_active:
            raise forms.ValidationError(
                "An inactive investigator cannot be assigned."
            )

        if (
            investigator.account_status
            != User.AccountStatus.ACTIVE
        ):
            raise forms.ValidationError(
                (
                    "The selected investigator does not have "
                    "an active account."
                )
            )

        return investigator

    def clean(self):
        """
        Perform form-level validation.

        CaseForm does not permit arbitrary workflow jumps. New cases begin
        Open, while existing-case status changes are handled only by
        CaseStatusForm.
        """

        cleaned_data = super().clean()

        status = cleaned_data.get(
            "status"
        )

        if "assigned_investigator" in self.fields:
            assigned_investigator = cleaned_data.get(
                "assigned_investigator"
            )
        else:
            assigned_investigator = (
                self.instance.assigned_investigator
                if self.is_update
                else None
            )

        if status == Case.Status.ARCHIVED:
            self.add_error(
                "status",
                (
                    "Use the dedicated Archive Case workflow to archive "
                    "a case."
                ),
            )

        if (
            not self.is_update
            and status not in {
                None,
                Case.Status.OPEN,
            }
        ):
            self.add_error(
                "status",
                "A newly created case must start in Open status.",
            )

        if (
            status == Case.Status.ASSIGNED
            and not assigned_investigator
        ):
            self.add_error(
                "assigned_investigator",
                (
                    "An investigator must be selected before the case "
                    "can enter Assigned status."
                ),
            )

        if (
            assigned_investigator
            and status == Case.Status.OPEN
        ):
            cleaned_data[
                "status"
            ] = Case.Status.ASSIGNED

        return cleaned_data

    def save(
        self,
        commit: bool = True,
    ) -> Case:
        """
        Save the case with normalized values.
        """

        case = super().save(
            commit=False
        )

        if (
            case.assigned_investigator
            and case.status == Case.Status.OPEN
        ):
            case.status = Case.Status.ASSIGNED

        if commit:
            case.save()
            self.save_m2m()

        return case


class CaseFilterForm(forms.Form):
    """
    Search and filter form used on the case listing page.
    """

    search = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": (
                    "Search by case number, title or description"
                ),
                "autocomplete": "off",
            }
        ),
    )

    crime_category = forms.ChoiceField(
        required=False,
        label="Crime Category",
        choices=[
            (
                "",
                "All Categories",
            ),
            *Case.CrimeCategory.choices,
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
            *Case.Priority.choices,
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
            *Case.Status.choices,
        ],
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    assigned_investigator = forms.ModelChoiceField(
        required=False,
        label="Investigator",
        queryset=User.objects.none(),
        empty_label="All Investigators",
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
                "Active Cases",
            ),
            (
                "inactive",
                "Inactive Cases",
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
                "case_title",
                "Title A-Z",
            ),
            (
                "-case_title",
                "Title Z-A",
            ),
            (
                "priority",
                "Priority",
            ),
            (
                "status",
                "Status",
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
        *args,
        **kwargs,
    ):
        """
        Load active investigators for filtering.
        """

        super().__init__(
            *args,
            **kwargs,
        )

        self.fields[
            "assigned_investigator"
        ].queryset = (
            User.objects
            .filter(
                role=User.Role.INVESTIGATOR,
                is_active=True,
            )
            .order_by(
                "full_name",
                "username",
            )
        )


class CaseStatusForm(forms.ModelForm):
    """
    Controlled form for case workflow transitions.

    ARCHIVED is deliberately excluded because archiving requires the
    dedicated confirmation/reason workflow.
    """

    class Meta:
        model = Case

        fields = [
            "status",
        ]

        widgets = {
            "status": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }

    def __init__(
        self,
        *args,
        current_user=None,
        **kwargs,
    ):
        super().__init__(
            *args,
            **kwargs,
        )

        self.current_user = current_user

        if not self.instance or not self.instance.pk:
            self.fields["status"].choices = []
            return

        current_status = self.instance.status

        if current_status == Case.Status.ARCHIVED:
            self.fields["status"].choices = [
                (
                    Case.Status.ARCHIVED,
                    self.instance.get_status_display(),
                ),
            ]
            self.fields["status"].disabled = True
            return

        allowed_statuses = get_allowed_case_statuses(
            self.instance,
            current_user=self.current_user,
        )

        status_labels = dict(
            Case.Status.choices
        )

        choices = [
            (
                current_status,
                f"Current: {status_labels[current_status]}",
            ),
        ]

        choices.extend(
            (
                status,
                status_labels[status],
            )
            for status in allowed_statuses
        )

        self.fields["status"].choices = choices

    def clean_status(self):
        status = self.cleaned_data.get(
            "status"
        )

        if status == Case.Status.ARCHIVED:
            raise forms.ValidationError(
                (
                    "Use the dedicated Archive Case workflow to archive "
                    "a case."
                )
            )

        if (
            self.instance
            and self.instance.pk
            and self.instance.status == Case.Status.ARCHIVED
        ):
            raise forms.ValidationError(
                (
                    "An archived case cannot be changed through the normal "
                    "status form. Restore it first."
                )
            )

        if not self.instance or not self.instance.pk:
            raise forms.ValidationError(
                "A saved case is required for a status transition."
            )

        current_status = self.instance.status

        # Selecting the existing state is safe and treated as a no-op.
        if status == current_status:
            return status

        allowed_statuses = get_allowed_case_statuses(
            self.instance,
            current_user=self.current_user,
        )

        if status not in allowed_statuses:
            current_label = self.instance.get_status_display()
            target_label = dict(
                Case.Status.choices
            ).get(
                status,
                str(status),
            )

            raise forms.ValidationError(
                (
                    f"Invalid case workflow transition: "
                    f"{current_label} → {target_label}."
                )
            )

        investigator_required_statuses = {
            Case.Status.ASSIGNED,
            Case.Status.UNDER_INVESTIGATION,
            Case.Status.EVIDENCE_COLLECTION,
            Case.Status.AI_ANALYSIS,
            Case.Status.REPORT_GENERATION,
        }

        if (
            status in investigator_required_statuses
            and self.instance.assigned_investigator_id is None
        ):
            raise forms.ValidationError(
                (
                    "Assign an investigator before moving this case "
                    "into the investigation workflow."
                )
            )

        return status


class CaseAssignmentForm(forms.ModelForm):
    """
    Assign or reassign a case to an active investigator.
    """

    class Meta:
        model = Case

        fields = [
            "assigned_investigator",
        ]

        widgets = {
            "assigned_investigator": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }

    def __init__(
        self,
        *args,
        **kwargs,
    ):
        """
        Limit assignment to active investigators.
        """

        super().__init__(
            *args,
            **kwargs,
        )

        self.fields[
            "assigned_investigator"
        ].queryset = (
            User.objects
            .filter(
                role=User.Role.INVESTIGATOR,
                account_status=User.AccountStatus.ACTIVE,
                is_active=True,
            )
            .order_by(
                "full_name",
                "username",
            )
        )

        self.fields[
            "assigned_investigator"
        ].empty_label = "Select investigator"

    def clean_assigned_investigator(self):
        """
        Validate selected investigator.
        """

        investigator = self.cleaned_data.get(
            "assigned_investigator"
        )

        if investigator is None:
            raise forms.ValidationError(
                "Please select an investigator."
            )

        if investigator.role != User.Role.INVESTIGATOR:
            raise forms.ValidationError(
                "Only investigators can be assigned to cases."
            )

        if not investigator.is_account_active:
            raise forms.ValidationError(
                "The selected investigator account is not active."
            )

        return investigator

    def save(
        self,
        commit: bool = True,
    ) -> Case:
        """
        Assign the investigator and update case status.
        """

        case = super().save(
            commit=False
        )

        if case.status == Case.Status.OPEN:
            case.status = Case.Status.ASSIGNED

        if commit:
            case.save()

        return case


class CaseArchiveForm(forms.Form):
    """
    Confirmation form for archiving a case.

    A meaningful reason is required because archive metadata is preserved on
    the Case record for auditability.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this case should be archived."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    reason = forms.CharField(
        required=True,
        min_length=10,
        max_length=1000,
        label="Archive Reason",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "placeholder": (
                    "Enter the reason for archiving this case"
                ),
                "rows": 4,
                "maxlength": "1000",
            }
        ),
    )

    def clean_reason(self) -> str:
        """
        Normalize and validate the archive reason.
        """

        reason = (
            self.cleaned_data
            .get(
                "reason",
                "",
            )
            .strip()
        )

        alphanumeric_count = sum(
            character.isalnum()
            for character in reason
        )

        if alphanumeric_count < 8:
            raise forms.ValidationError(
                (
                    "Enter a meaningful archive reason containing at least "
                    "8 letters or numbers."
                )
            )

        return reason


class CaseRestoreForm(forms.Form):
    """
    Confirmation form for restoring an archived case.
    """

    confirmation = forms.BooleanField(
        required=True,
        label=(
            "I confirm that this archived case should be restored."
        ),
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )