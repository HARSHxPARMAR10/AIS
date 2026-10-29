"""

AIDEX AI Engine Prompt Library

Centralized, versioned and token-conscious forensic prompt templates for
Gemini-powered evidence analysis.

Design principles
-----------------
- Prompts remain compact to protect free-tier token usage.
- Every prompt clearly separates observations from inference.
- The AI must not invent evidence, identities, timestamps or technical facts.
- Responses must remain JSON-compatible for stable parsing.
- Prompt selection is based on AIAnalysis.AnalysisType.
- Custom prompts are sanitized and wrapped inside the same forensic safety
  instructions as built-in prompts.
- Prompt versioning supports auditability and future upgrades.

This module does not call Gemini. It only builds structured instructions for
the provider layer or service orchestration layer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .models import AIAnalysis


# ==========================================================
# Prompt Constants
# ==========================================================

PROMPT_VERSION_V1 = "v1"

DEFAULT_PROMPT_VERSION = PROMPT_VERSION_V1

# Increment whenever prompt rendering, safety rules, multimodal instructions
# or analysis-type definitions change in a result-affecting way. The service
# layer includes this revision in the cache identity.
PROMPT_LIBRARY_REVISION = "promptlib-v4-retry-safe-structured-output"

SUPPORTED_PROMPT_VERSIONS = {
    PROMPT_VERSION_V1,
}

MAX_CUSTOM_PROMPT_LENGTH = 4_000
MAX_CONTEXT_LENGTH = 50_000
MAX_TITLE_LENGTH = 200

SEVERITY_VALUES = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

THREAT_LEVEL_VALUES = (
    "UNKNOWN",
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


# ==========================================================
# Exceptions
# ==========================================================

class PromptError(Exception):
    """Base error for AIDEX prompt operations."""


class UnsupportedPromptVersionError(PromptError):
    """Raised when an unknown prompt version is requested."""


class InvalidCustomPromptError(PromptError):
    """Raised when a custom prompt is empty or unsafe."""


class PromptContextError(PromptError):
    """Raised when prompt context is missing or invalid."""


# ==========================================================
# Data Objects
# ==========================================================

@dataclass(frozen=True, slots=True)
class PromptDefinition:
    """
    One versioned forensic prompt definition.
    """

    key: str
    title: str
    objective: str
    instructions: tuple[str, ...]
    expected_focus: tuple[str, ...]
    version: str = DEFAULT_PROMPT_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "objective": self.objective,
            "instructions": list(
                self.instructions
            ),
            "expected_focus": list(
                self.expected_focus
            ),
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class PromptBuildResult:
    """
    Final prompt package returned to the AI service.
    """

    prompt: str
    prompt_key: str
    prompt_title: str
    prompt_version: str
    estimated_characters: int
    was_truncated: bool
    prompt_library_revision: str = PROMPT_LIBRARY_REVISION

    def as_metadata(self) -> dict[str, Any]:
        return {
            "prompt_key": self.prompt_key,
            "prompt_title": self.prompt_title,
            "prompt_version": self.prompt_version,
            "prompt_library_revision": self.prompt_library_revision,
            "estimated_characters": self.estimated_characters,
            "was_truncated": self.was_truncated,
        }


# ==========================================================
# JSON Response Contract
# ==========================================================

FORENSIC_RESPONSE_SCHEMA = {
    "summary": (
        "Concise evidence-grounded summary. "
        "Clearly separate observation from inference."
    ),
    "confidence_score": (
        "Number from 0 to 100, or null when confidence cannot be estimated."
    ),
    "risk_score": (
        "Number from 0 to 100, or null when risk cannot be estimated."
    ),
    "threat_level": (
        "One of UNKNOWN, NONE, LOW, MEDIUM, HIGH or CRITICAL."
    ),
    "extracted_text": (
        "Relevant extracted or normalized text, otherwise empty string."
    ),
    "keywords": [
        "Important keyword or indicator",
    ],
    "entities": [
        {
            "type": (
                "Entity category such as PERSON, ORGANIZATION, EMAIL, "
                "DOMAIN, IP_ADDRESS, FILE_HASH or OTHER."
            ),
            "value": "Observed entity value.",
            "context": "Brief evidence-grounded context.",
        }
    ],
    "findings": [
        {
            "title": "Short finding title.",
            "description": (
                "Evidence-grounded finding. "
                "State uncertainty when appropriate."
            ),
            "severity": (
                "One of INFO, LOW, MEDIUM, HIGH or CRITICAL."
            ),
            "confidence": (
                "Number from 0 to 100, or null."
            ),
        }
    ],
    "recommendations": (
        "Practical next investigative steps, verification actions "
        "and important limitations."
    ),
}


# ==========================================================
# Shared Safety Instructions
# ==========================================================

SYSTEM_INSTRUCTION = """
You are AIDEX, an AI assistant supporting authorized digital evidence
investigators.

Follow these rules:

1. Use only the information explicitly supplied in the prompt.
2. Never invent names, messages, file contents, timestamps, indicators,
   hashes, identities, events or forensic conclusions.
3. Clearly distinguish direct observation from inference.
4. Mention when a file, image, video, audio stream or binary object was not
   directly inspected. When original supported media is attached, direct
   observations from that attachment are allowed.
5. Never identify a real person from an image or video. Use anonymous labels
   such as "Person 1" when a reference is necessary.
6. Do not claim definitive deepfake, tampering, identity, intent or authorship
   from appearance alone. Report observable indicators and uncertainty.
7. Treat AI output as investigative assistance, not final legal proof.
8. Avoid exposing unnecessary personal, confidential or secret data.
9. Do not provide instructions that enable abuse, malware deployment,
   credential theft, evasion or unauthorized access.
10. Return exactly one valid JSON object.
11. Do not wrap the JSON in markdown or commentary.
12. Follow the supplied response schema exactly.
"""


COMMON_ANALYSIS_RULES = (
    "Use only supplied evidence content and metadata.",
    "Do not invent missing evidence.",
    "Separate observation from inference.",
    "Mention important limitations.",
    "Keep findings concise and investigation-focused.",
    "Return only one valid JSON object.",
)


# ==========================================================
# Prompt Definitions
# ==========================================================

GENERAL_FORENSIC_PROMPT = PromptDefinition(
    key="GENERAL_FORENSIC_REVIEW",
    title="General Forensic Review",
    objective=(
        "Review the supplied digital evidence for relevant facts, suspicious "
        "indicators, investigation value, limitations and next steps."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Identify notable patterns, inconsistencies and investigation leads.",
        "Avoid overstating risk when the evidence is incomplete.",
    ),
    expected_focus=(
        "Evidence relevance",
        "Suspicious indicators",
        "Limitations",
        "Next investigative actions",
    ),
)


OCR_PROMPT = PromptDefinition(
    key="OCR_TEXT_EXTRACTION",
    title="OCR Text Extraction",
    objective=(
        "Extract and normalize text from attached supported evidence when "
        "available, together with supplied derived text and metadata, without "
        "inventing unreadable content."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Preserve important names, numbers, dates, URLs and identifiers.",
        "Mark uncertain or partial text clearly.",
        "Do not guess characters that are unreadable.",
        "Place the best normalized text in extracted_text.",
    ),
    expected_focus=(
        "Readable text",
        "Dates and timestamps",
        "Identifiers",
        "URLs and contact details",
    ),
)


DOCUMENT_PROMPT = PromptDefinition(
    key="DOCUMENT_EVIDENCE_REVIEW",
    title="Document Evidence Review",
    objective=(
        "Analyze an attached supported document such as PDF when available, "
        "plus supplied document text and metadata, for facts, inconsistencies, "
        "entities and investigation relevance."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Identify important clauses, claims, dates, names and transaction details.",
        "Highlight contradictions or suspicious wording only when supported.",
        "Summarize long content without omitting critical context.",
    ),
    expected_focus=(
        "Important statements",
        "Dates and identities",
        "Financial or legal indicators",
        "Contradictions",
    ),
)


IMAGE_PROMPT = PromptDefinition(
    key="IMAGE_EVIDENCE_REVIEW",
    title="Image Evidence Review",
    objective=(
        "Analyze the attached image directly when available, together with "
        "OCR output and metadata, for observable evidence, suspicious "
        "indicators and investigation value."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "When original image media is attached, report direct visual observations.",
        "When no image is attached, do not invent visual details.",
        "Do not identify real people or infer sensitive traits from appearance.",
        "Separate OCR-derived text, direct observation and inference.",
        "Treat manipulation indicators as non-definitive and recommend specialist verification.",
    ),
    expected_focus=(
        "Visible or described objects",
        "OCR text",
        "Scene context",
        "Metadata",
    ),
)


VIDEO_PROMPT = PromptDefinition(
    key="VIDEO_EVIDENCE_REVIEW",
    title="Video Evidence Review",
    objective=(
        "Analyze attached video directly when available, together with frame "
        "summaries, transcript excerpts and metadata, for relevant events, "
        "sequence, observable entities and risk."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "When original video is attached, report direct scene and timeline observations.",
        "When no video is attached, do not invent unseen frames or events.",
        "Use anonymous person labels and never identify real people from appearance.",
        "Separate transcript content, direct visual observation and inference.",
        "Describe edits or discontinuities only as observable indicators, not definitive tampering.",
    ),
    expected_focus=(
        "Event sequence",
        "Transcript content",
        "Visible entities",
        "Timing and continuity",
    ),
)


AUDIO_PROMPT = PromptDefinition(
    key="AUDIO_EVIDENCE_REVIEW",
    title="Audio Evidence Review",
    objective=(
        "Analyze attached audio directly when available, together with "
        "transcripts, speaker labels and metadata, for relevant statements, "
        "indicators, uncertainty and investigation value."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Transcribe relevant speech from attached audio when possible.",
        "Use anonymous speaker labels unless identity is explicitly supplied in evidence context.",
        "Mark uncertain or inaudible transcription content.",
        "Highlight threats, demands, admissions or suspicious statements only when supported.",
    ),
    expected_focus=(
        "Statements",
        "Speaker labels",
        "Threat indicators",
        "Transcript uncertainty",
    ),
)


EMAIL_PROMPT = PromptDefinition(
    key="EMAIL_EVIDENCE_REVIEW",
    title="Email Evidence Review",
    objective=(
        "Analyze supplied email headers, body content and metadata for phishing, "
        "fraud, impersonation, social engineering and technical indicators."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Review sender, recipient, subject, URLs, domains and header indicators.",
        "Identify urgency, credential requests, payment requests and impersonation.",
        "Do not classify an email as malicious without explaining evidence.",
    ),
    expected_focus=(
        "Sender authenticity",
        "Phishing indicators",
        "URLs and domains",
        "Social engineering",
    ),
)


CHAT_PROMPT = PromptDefinition(
    key="CHAT_EVIDENCE_REVIEW",
    title="Chat Evidence Review",
    objective=(
        "Analyze supplied chat messages for chronology, participants, suspicious "
        "requests, coercion, fraud indicators and investigation relevance."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Preserve chronology and speaker attribution when provided.",
        "Identify transaction, credential, threat or impersonation indicators.",
        "Do not infer participant identity beyond supplied information.",
    ),
    expected_focus=(
        "Conversation chronology",
        "Participants",
        "Suspicious requests",
        "Fraud or threat indicators",
    ),
)


LOG_PROMPT = PromptDefinition(
    key="LOG_EVIDENCE_REVIEW",
    title="Log Evidence Review",
    objective=(
        "Analyze supplied system, application, security or network log content "
        "for anomalies, indicators, sequence and likely investigation value."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Preserve IP addresses, domains, paths, event IDs and timestamps.",
        "Identify repeated failures, unusual access and suspicious sequences.",
        "Do not claim compromise solely from one ambiguous event.",
    ),
    expected_focus=(
        "Timestamps",
        "IP addresses and domains",
        "Authentication events",
        "Anomalies",
    ),
)


METADATA_PROMPT = PromptDefinition(
    key="METADATA_ANALYSIS",
    title="Metadata Analysis",
    objective=(
        "Review supplied file and evidence metadata for inconsistencies, "
        "timeline value, integrity concerns and investigation relevance."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Compare filenames, extensions, hashes, sizes and timestamps.",
        "Identify inconsistencies without assuming malicious intent.",
        "Explain what cannot be concluded from metadata alone.",
    ),
    expected_focus=(
        "File attributes",
        "Hash and integrity",
        "Timeline",
        "Metadata inconsistencies",
    ),
)


FILE_INTEGRITY_PROMPT = PromptDefinition(
    key="FILE_INTEGRITY_ANALYSIS",
    title="File Integrity Analysis",
    objective=(
        "Assess supplied file integrity metadata, hashes and verification "
        "information for consistency and forensic reliability."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Treat SHA-256 values as identifiers, not proof of authenticity alone.",
        "Identify missing or changed integrity values.",
        "Recommend independent verification where required.",
    ),
    expected_focus=(
        "SHA-256 consistency",
        "Verification status",
        "File metadata",
        "Integrity limitations",
    ),
)


MALWARE_PROMPT = PromptDefinition(
    key="MALWARE_ANALYSIS",
    title="Malware Analysis",
    objective=(
        "Analyze supplied static indicators, filenames, hashes, strings, logs "
        "and metadata for potential malware-related evidence."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Do not provide malware deployment, evasion or exploitation instructions.",
        "Distinguish suspicious indicators from confirmed malware behavior.",
        "Recommend safe sandboxing and independent scanning where appropriate.",
    ),
    expected_focus=(
        "Static indicators",
        "Suspicious filenames and strings",
        "Behavioral clues",
        "Safe verification steps",
    ),
)


NETWORK_PROMPT = PromptDefinition(
    key="NETWORK_ANALYSIS",
    title="Network Analysis",
    objective=(
        "Analyze supplied network logs, IP addresses, domains, ports and event "
        "sequences for suspicious communication and investigation value."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Preserve technical indicators exactly as supplied.",
        "Identify unusual traffic patterns without overstating causation.",
        "Recommend correlation with firewall, DNS and endpoint logs.",
    ),
    expected_focus=(
        "IP addresses",
        "Domains",
        "Ports and protocols",
        "Traffic anomalies",
    ),
)


KEYWORD_PROMPT = PromptDefinition(
    key="KEYWORD_EXTRACTION",
    title="Keyword Extraction",
    objective=(
        "Extract concise, investigation-relevant keywords, entities and "
        "technical indicators from the supplied evidence."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Prefer meaningful indicators over generic words.",
        "Deduplicate keywords.",
        "Preserve exact technical indicators.",
    ),
    expected_focus=(
        "Keywords",
        "Entities",
        "Technical indicators",
        "Investigation themes",
    ),
)


THREAT_PROMPT = PromptDefinition(
    key="THREAT_ASSESSMENT",
    title="Threat Assessment",
    objective=(
        "Assess the supplied evidence for threat indicators, likely impact, "
        "confidence, uncertainty and recommended investigative action."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Base risk and threat level only on supplied evidence.",
        "Explain important factors supporting the risk assessment.",
        "Avoid critical ratings without strong evidence.",
    ),
    expected_focus=(
        "Threat indicators",
        "Potential impact",
        "Risk score",
        "Confidence and limitations",
    ),
)


FACE_DETECTION_PROMPT = PromptDefinition(
    key="FACE_DETECTION_REVIEW",
    title="Face Detection Review",
    objective=(
        "Review supplied face-detection output and image metadata for count, "
        "quality, uncertainty and investigation relevance."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Do not identify a person unless identity is explicitly supplied.",
        "Do not infer protected or sensitive traits.",
        "Report detection confidence and image limitations.",
    ),
    expected_focus=(
        "Face count",
        "Detection confidence",
        "Image quality",
        "Limitations",
    ),
)


OBJECT_DETECTION_PROMPT = PromptDefinition(
    key="OBJECT_DETECTION_REVIEW",
    title="Object Detection Review",
    objective=(
        "Review supplied object-detection output and image or video metadata "
        "for relevant objects, uncertainty and investigation value."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Do not claim an object was observed unless supplied detection data supports it.",
        "Preserve confidence values when provided.",
        "Avoid legal conclusions based only on object labels.",
    ),
    expected_focus=(
        "Detected objects",
        "Confidence",
        "Scene relevance",
        "Limitations",
    ),
)


CUSTOM_PROMPT_DEFINITION = PromptDefinition(
    key="CUSTOM",
    title="Custom Forensic Analysis",
    objective=(
        "Complete the authorized custom forensic analysis request while "
        "following all AIDEX safety and evidence-grounding rules."
    ),
    instructions=(
        *COMMON_ANALYSIS_RULES,
        "Treat the custom request as an investigation objective, not as permission "
        "to invent missing evidence.",
    ),
    expected_focus=(
        "Custom investigation objective",
        "Evidence-grounded findings",
        "Limitations",
        "Next steps",
    ),
)


# ==========================================================
# Registry
# ==========================================================

PROMPT_REGISTRY: dict[str, PromptDefinition] = {
    GENERAL_FORENSIC_PROMPT.key: GENERAL_FORENSIC_PROMPT,
    OCR_PROMPT.key: OCR_PROMPT,
    DOCUMENT_PROMPT.key: DOCUMENT_PROMPT,
    IMAGE_PROMPT.key: IMAGE_PROMPT,
    VIDEO_PROMPT.key: VIDEO_PROMPT,
    AUDIO_PROMPT.key: AUDIO_PROMPT,
    EMAIL_PROMPT.key: EMAIL_PROMPT,
    CHAT_PROMPT.key: CHAT_PROMPT,
    LOG_PROMPT.key: LOG_PROMPT,
    METADATA_PROMPT.key: METADATA_PROMPT,
    FILE_INTEGRITY_PROMPT.key: FILE_INTEGRITY_PROMPT,
    MALWARE_PROMPT.key: MALWARE_PROMPT,
    NETWORK_PROMPT.key: NETWORK_PROMPT,
    KEYWORD_PROMPT.key: KEYWORD_PROMPT,
    THREAT_PROMPT.key: THREAT_PROMPT,
    FACE_DETECTION_PROMPT.key: FACE_DETECTION_PROMPT,
    OBJECT_DETECTION_PROMPT.key: OBJECT_DETECTION_PROMPT,
    CUSTOM_PROMPT_DEFINITION.key: CUSTOM_PROMPT_DEFINITION,
}


ANALYSIS_TYPE_PROMPT_MAP: dict[str, str] = {
    AIAnalysis.AnalysisType.GENERAL: GENERAL_FORENSIC_PROMPT.key,
    AIAnalysis.AnalysisType.OCR: OCR_PROMPT.key,
    AIAnalysis.AnalysisType.DOCUMENT: DOCUMENT_PROMPT.key,
    AIAnalysis.AnalysisType.IMAGE: IMAGE_PROMPT.key,
    AIAnalysis.AnalysisType.VIDEO: VIDEO_PROMPT.key,
    AIAnalysis.AnalysisType.AUDIO: AUDIO_PROMPT.key,
    AIAnalysis.AnalysisType.FACE_DETECTION: FACE_DETECTION_PROMPT.key,
    AIAnalysis.AnalysisType.OBJECT_DETECTION: OBJECT_DETECTION_PROMPT.key,
    AIAnalysis.AnalysisType.METADATA: METADATA_PROMPT.key,
    AIAnalysis.AnalysisType.FILE_INTEGRITY: FILE_INTEGRITY_PROMPT.key,
    AIAnalysis.AnalysisType.MALWARE: MALWARE_PROMPT.key,
    AIAnalysis.AnalysisType.EMAIL: EMAIL_PROMPT.key,
    AIAnalysis.AnalysisType.CHAT: CHAT_PROMPT.key,
    AIAnalysis.AnalysisType.LOG: LOG_PROMPT.key,
    AIAnalysis.AnalysisType.NETWORK: NETWORK_PROMPT.key,
    AIAnalysis.AnalysisType.KEYWORD_EXTRACTION: KEYWORD_PROMPT.key,
    AIAnalysis.AnalysisType.THREAT_ASSESSMENT: THREAT_PROMPT.key,
    AIAnalysis.AnalysisType.CUSTOM: CUSTOM_PROMPT_DEFINITION.key,
}


# ==========================================================
# Text Utilities
# ==========================================================

def normalize_whitespace(
    value: Any,
) -> str:
    """
    Normalize spaces while preserving readable paragraphs.
    """

    text = str(
        value or ""
    ).replace(
        "\r\n",
        "\n",
    ).replace(
        "\r",
        "\n",
    )

    normalized_lines: list[str] = []

    previous_blank = False

    for raw_line in text.splitlines():
        line = re.sub(
            r"[ \t]+",
            " ",
            raw_line,
        ).strip()

        is_blank = not line

        if is_blank and previous_blank:
            continue

        normalized_lines.append(
            line
        )

        previous_blank = is_blank

    return "\n".join(
        normalized_lines
    ).strip()


def truncate_text(
    value: Any,
    maximum_length: int,
) -> tuple[str, bool]:
    """
    Truncate text and report whether truncation occurred.
    """

    text = str(
        value or ""
    )

    if len(text) <= maximum_length:
        return text, False

    return text[
        :maximum_length
    ], True


def sanitize_custom_prompt(
    value: Any,
) -> str:
    """
    Validate and sanitize a custom forensic request.
    """

    prompt = normalize_whitespace(
        value
    )

    if len(prompt) < 20:
        raise InvalidCustomPromptError(
            "Custom prompt must contain at least 20 characters."
        )

    if len(prompt) > MAX_CUSTOM_PROMPT_LENGTH:
        raise InvalidCustomPromptError(
            (
                "Custom prompt exceeds the maximum allowed length "
                f"of {MAX_CUSTOM_PROMPT_LENGTH} characters."
            )
        )

    blocked_patterns = (
        r"\bignore\s+(all|any|previous|prior)\s+instructions\b",
        r"\breveal\s+(the\s+)?system\s+prompt\b",
        r"\bshow\s+(the\s+)?hidden\s+instructions\b",
        r"\bdisable\s+safety\b",
        r"\bbypass\s+(the\s+)?rules\b",
    )

    for pattern in blocked_patterns:
        if re.search(
            pattern,
            prompt,
            re.IGNORECASE,
        ):
            raise InvalidCustomPromptError(
                (
                    "Custom prompt contains unsupported instruction-manipulation "
                    "language."
                )
            )

    return prompt


def make_json_safe(
    value: Any,
) -> Any:
    """
    Convert arbitrary prompt context into JSON-safe values.
    """

    if value is None or isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): make_json_safe(
                item_value
            )
            for key, item_value in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            make_json_safe(
                item
            )
            for item in value
        ]

    return str(
        value
    )


# ==========================================================
# Prompt Lookup
# ==========================================================

def validate_prompt_version(
    version: str,
) -> str:
    """
    Validate and normalize prompt version.
    """

    normalized_version = str(
        version or DEFAULT_PROMPT_VERSION
    ).strip().lower()

    if normalized_version not in SUPPORTED_PROMPT_VERSIONS:
        raise UnsupportedPromptVersionError(
            f"Unsupported prompt version: {normalized_version}"
        )

    return normalized_version


def get_prompt_definition(
    prompt_key: str,
    *,
    version: str = DEFAULT_PROMPT_VERSION,
) -> PromptDefinition:
    """
    Return one registered prompt definition.
    """

    normalized_version = validate_prompt_version(
        version
    )

    normalized_key = str(
        prompt_key or ""
    ).strip().upper()

    prompt_definition = PROMPT_REGISTRY.get(
        normalized_key
    )

    if prompt_definition is None:
        raise PromptError(
            f"Unknown prompt key: {normalized_key}"
        )

    if prompt_definition.version != normalized_version:
        raise UnsupportedPromptVersionError(
            (
                f"Prompt '{normalized_key}' is not available "
                f"for version '{normalized_version}'."
            )
        )

    return prompt_definition


def get_prompt_for_analysis_type(
    analysis_type: str,
    *,
    version: str = DEFAULT_PROMPT_VERSION,
) -> PromptDefinition:
    """
    Return the prompt mapped to an AIAnalysis analysis type.
    """

    prompt_key = ANALYSIS_TYPE_PROMPT_MAP.get(
        analysis_type,
        GENERAL_FORENSIC_PROMPT.key,
    )

    return get_prompt_definition(
        prompt_key,
        version=version,
    )


def list_prompt_definitions(
    *,
    version: str = DEFAULT_PROMPT_VERSION,
) -> list[PromptDefinition]:
    """
    Return all prompt definitions for a version.
    """

    normalized_version = validate_prompt_version(
        version
    )

    return sorted(
        [
            prompt
            for prompt in PROMPT_REGISTRY.values()
            if prompt.version == normalized_version
        ],
        key=lambda prompt: prompt.title,
    )


# ==========================================================
# Context Builders
# ==========================================================

def build_analysis_context(
    analysis: AIAnalysis,
    *,
    evidence_text: str = "",
    additional_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build structured forensic context from an AIAnalysis record.
    """

    if analysis is None:
        raise PromptContextError(
            "AI analysis instance is required."
        )

    evidence = analysis.evidence
    case = evidence.case

    context: dict[str, Any] = {
        "analysis": {
            "analysis_number": analysis.analysis_number,
            "title": analysis.title,
            "analysis_type": analysis.get_analysis_type_display(),
            "priority": analysis.get_priority_display(),
            "provider": analysis.get_provider_display(),
            "prompt_version": analysis.prompt_version,
        },
        "case": {
            "case_number": case.case_number,
            "case_title": case.case_title,
            "crime_category": case.get_crime_category_display(),
            "priority": case.get_priority_display(),
            "status": case.get_status_display(),
            "description": normalize_whitespace(
                case.description
            ),
        },
        "evidence": {
            "evidence_title": evidence.evidence_title,
            "description": normalize_whitespace(
                evidence.description
            ),
            "evidence_type": evidence.get_evidence_type_display(),
            "original_filename": (
                evidence.original_filename
                or evidence.filename
            ),
            "file_extension": evidence.file_extension,
            "file_size_bytes": evidence.file_size,
            "sha256_hash": evidence.sha256_hash,
            "verification_status": (
                evidence.get_verification_status_display()
            ),
        },
        "derived_content": normalize_whitespace(
            evidence_text
        ),
    }

    if additional_context:
        context[
            "additional_context"
        ] = make_json_safe(
            additional_context
        )

    return context


def compact_context(
    context: Mapping[str, Any],
    *,
    maximum_characters: int = MAX_CONTEXT_LENGTH,
) -> tuple[str, bool]:
    """
    Serialize and truncate prompt context.
    """

    serialized = json.dumps(
        make_json_safe(
            context
        ),
        ensure_ascii=False,
        indent=2,
    )

    return truncate_text(
        serialized,
        maximum_characters,
    )


# ==========================================================
# Prompt Rendering
# ==========================================================

def render_instruction_block(
    prompt_definition: PromptDefinition,
) -> str:
    """
    Render numbered prompt instructions.
    """

    return "\n".join(
        f"{index}. {instruction}"
        for index, instruction in enumerate(
            prompt_definition.instructions,
            start=1,
        )
    )


def render_focus_block(
    prompt_definition: PromptDefinition,
) -> str:
    """
    Render expected analysis focus.
    """

    return "\n".join(
        f"- {focus}"
        for focus in prompt_definition.expected_focus
    )


def render_response_schema() -> str:
    """
    Render the JSON response contract.
    """

    return json.dumps(
        FORENSIC_RESPONSE_SCHEMA,
        ensure_ascii=False,
        indent=2,
    )


def render_media_instruction_block(
    media_context: Mapping[str, Any] | None,
) -> str:
    """
    Render media-specific instructions that reflect what the service actually
    attached to the provider request.
    """

    safe_context = make_json_safe(
        media_context or {}
    )

    media_attached = bool(
        safe_context.get("media_attached")
    )

    source_kind = str(
        safe_context.get("source_kind")
        or "unknown"
    )

    mime_type = str(
        safe_context.get("mime_type")
        or "unknown"
    )

    if media_attached:
        return normalize_whitespace(
            f"""
            ORIGINAL MEDIA STATUS
            - Original supported evidence media is attached to this request.
            - Provider input source: {source_kind}
            - MIME type: {mime_type}
            - Inspect only the supplied attachment and forensic context.
            - Clearly separate direct media observation from derived text and inference.
            - For image/video content, never identify real people from appearance.
            - Do not present deepfake, manipulation, intent or authorship as definitive
              unless independently established by supplied evidence.
            """
        )

    return normalize_whitespace(
        f"""
        ORIGINAL MEDIA STATUS
        - No original supported media attachment is available to inspect directly.
        - Provider input source: {source_kind}
        - Base the analysis only on supplied metadata and derived/extracted content.
        - Do not invent visual, audio, video or document observations.
        """
    )


def build_prompt(
    *,
    prompt_definition: PromptDefinition,
    context: Mapping[str, Any],
    custom_prompt: str = "",
    requested_focus: str = "",
    media_context: Mapping[str, Any] | None = None,
    maximum_context_characters: int = MAX_CONTEXT_LENGTH,
) -> PromptBuildResult:
    """
    Build one complete structured forensic prompt.
    """

    compacted_context, was_truncated = compact_context(
        context,
        maximum_characters=maximum_context_characters,
    )

    objective = prompt_definition.objective

    if prompt_definition.key == CUSTOM_PROMPT_DEFINITION.key:
        objective = sanitize_custom_prompt(
            custom_prompt
        )

    normalized_requested_focus = normalize_whitespace(
        requested_focus
    )

    requested_focus_block = (
        normalized_requested_focus
        if normalized_requested_focus
        else "No additional user-requested focus was supplied."
    )

    media_instruction_block = render_media_instruction_block(
        media_context
    )

    prompt_text = normalize_whitespace(
        f"""
        PROMPT TITLE
        {prompt_definition.title}

        PROMPT VERSION
        {prompt_definition.version}

        PROMPT LIBRARY REVISION
        {PROMPT_LIBRARY_REVISION}

        ANALYSIS OBJECTIVE
        {objective}

        USER-REQUESTED FOCUS
        {requested_focus_block}

        ANALYSIS INSTRUCTIONS
        {render_instruction_block(prompt_definition)}

        EXPECTED ANALYSIS FOCUS
        {render_focus_block(prompt_definition)}

        {media_instruction_block}

        STRUCTURED OUTPUT CONTRACT
        The provider API applies the machine-readable JSON response schema.
        Return only evidence-grounded values for that schema.
        Do not add Markdown fences, commentary before or after the result,
        or repeat the schema itself.
        Keep summaries, findings, entities and recommendations concise enough
        to complete the full structured response without truncation.

        FORENSIC CONTEXT
        {compacted_context}
        """
    )

    return PromptBuildResult(
        prompt=prompt_text,
        prompt_key=prompt_definition.key,
        prompt_title=prompt_definition.title,
        prompt_version=prompt_definition.version,
        estimated_characters=len(
            prompt_text
        ),
        was_truncated=was_truncated,
        prompt_library_revision=PROMPT_LIBRARY_REVISION,
    )


def get_clean_requested_focus(
    analysis: AIAnalysis,
) -> str:
    """
    Return only genuine user-requested focus for built-in analyses.

    Older AIDEX service versions could save the entire generated provider
    prompt into analysis.request_prompt. Reusing that value on Retry would
    recursively embed the previous prompt inside the next prompt, making the
    request unnecessarily large and increasing truncation risk.

    Generated-prompt markers are therefore detected and ignored. Custom
    analysis requests are handled separately and are not filtered here.
    """

    requested_focus = normalize_whitespace(
        getattr(
            analysis,
            "request_prompt",
            "",
        )
    )

    if not requested_focus:
        return ""

    generated_prompt_markers = (
        "PROMPT TITLE",
        "PROMPT VERSION",
        "ANALYSIS OBJECTIVE",
        "FORENSIC CONTEXT",
    )

    marker_matches = sum(
        marker in requested_focus
        for marker in generated_prompt_markers
    )

    if marker_matches >= 3:
        return ""

    return requested_focus


def build_prompt_for_analysis(
    analysis: AIAnalysis,
    *,
    evidence_text: str = "",
    custom_prompt: str = "",
    additional_context: Mapping[str, Any] | None = None,
    media_context: Mapping[str, Any] | None = None,
    maximum_context_characters: int = MAX_CONTEXT_LENGTH,
) -> PromptBuildResult:
    """
    Build the correct prompt for an AIAnalysis record.
    """

    prompt_version = validate_prompt_version(
        analysis.prompt_version
        or DEFAULT_PROMPT_VERSION
    )

    prompt_definition = get_prompt_for_analysis_type(
        analysis.analysis_type,
        version=prompt_version,
    )

    selected_custom_prompt = custom_prompt
    requested_focus = ""

    if prompt_definition.key == CUSTOM_PROMPT_DEFINITION.key:
        if not selected_custom_prompt:
            selected_custom_prompt = analysis.request_prompt
    else:
        requested_focus = get_clean_requested_focus(
            analysis
        )

    context = build_analysis_context(
        analysis,
        evidence_text=evidence_text,
        additional_context=additional_context,
    )

    return build_prompt(
        prompt_definition=prompt_definition,
        context=context,
        custom_prompt=selected_custom_prompt,
        requested_focus=requested_focus,
        media_context=media_context,
        maximum_context_characters=maximum_context_characters,
    )


# ==========================================================
# Compatibility Helpers
# ==========================================================

def get_prompt_key_for_analysis_type(
    analysis_type: str,
) -> str:
    """
    Return the registered prompt key for an analysis type.
    """

    return ANALYSIS_TYPE_PROMPT_MAP.get(
        analysis_type,
        GENERAL_FORENSIC_PROMPT.key,
    )


def get_prompt_choice_list(
    *,
    version: str = DEFAULT_PROMPT_VERSION,
) -> list[tuple[str, str]]:
    """
    Return form-ready prompt choices.
    """

    return [
        (
            prompt.key,
            prompt.title,
        )
        for prompt in list_prompt_definitions(
            version=version
        )
    ]


def get_system_instruction() -> str:
    """
    Return the normalized AIDEX system instruction.
    """

    return normalize_whitespace(
        SYSTEM_INSTRUCTION
    )


def validate_response_shape(
    payload: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """
    Perform lightweight validation of parsed provider JSON.
    """

    required_keys = {
        "summary",
        "confidence_score",
        "risk_score",
        "threat_level",
        "extracted_text",
        "keywords",
        "entities",
        "findings",
        "recommendations",
    }

    missing_keys = sorted(
        required_keys.difference(
            payload.keys()
        )
    )

    errors: list[str] = []

    if missing_keys:
        errors.append(
            "Missing keys: "
            + ", ".join(
                missing_keys
            )
        )

    threat_level = str(
        payload.get(
            "threat_level",
            "",
        )
    ).strip().upper()

    if (
        threat_level
        and threat_level not in THREAT_LEVEL_VALUES
    ):
        errors.append(
            "Invalid threat_level value."
        )

    findings = payload.get(
        "findings"
    )

    if findings is not None and not isinstance(
        findings,
        list,
    ):
        errors.append(
            "findings must be a list."
        )

    entities = payload.get(
        "entities"
    )

    if entities is not None and not isinstance(
        entities,
        list,
    ):
        errors.append(
            "entities must be a list."
        )

    keywords = payload.get(
        "keywords"
    )

    if keywords is not None and not isinstance(
        keywords,
        list,
    ):
        errors.append(
            "keywords must be a list."
        )

    return (
        not errors,
        errors,
    )