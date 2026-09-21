import os
from typing import List, Tuple
from security.models import AttachmentAnalysisResult, AttachmentDetails


class StaticAttachmentInspector:
    """
    Static Attachment Analysis Module for Member 4.
    Detects dangerous file extensions, double extensions, and macro-enabled documents.
    """

    DANGEROUS_EXTENSIONS = [
        ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1",
        ".iso", ".img", ".jar", ".cpl", ".hta", ".wsf", ".lnk",
        ".docm", ".xlsm", ".pptm"
    ]

    INNOCENT_PREFIX_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"]

    def analyze_attachments(self, attachments_input: List[str]) -> AttachmentAnalysisResult:
        if not attachments_input:
            return AttachmentAnalysisResult()

        total = len(attachments_input)
        dangerous_count = 0
        has_double_ext = False
        details_list: List[AttachmentDetails] = []
        findings: List[str] = []

        for filename in attachments_input:
            clean_name = os.path.basename(filename.strip().lower())
            name_parts = clean_name.split(".")

            is_danger = False
            is_double = False
            reason = None

            # Check double extension (e.g. Invoice_2026.pdf.exe)
            if len(name_parts) >= 3:
                second_last_ext = "." + name_parts[-2]
                last_ext = "." + name_parts[-1]

                if second_last_ext in self.INNOCENT_PREFIX_EXTENSIONS and last_ext in self.DANGEROUS_EXTENSIONS:
                    is_danger = True
                    is_double = True
                    has_double_ext = True
                    reason = f"Double extension spoofing detected: '{second_last_ext}' followed by dangerous extension '{last_ext}'"
                    findings.append(f"Double extension spoofing in attachment '{clean_name}': disguised as PDF/document but ends with '{last_ext}'.")

            # Check standard dangerous extension
            if not is_danger:
                _, ext = os.path.splitext(clean_name)
                if ext in self.DANGEROUS_EXTENSIONS:
                    is_danger = True
                    reason = f"High-risk file extension '{ext}' detected."
                    findings.append(f"Dangerous attachment flagged: '{clean_name}' has risky extension '{ext}'.")

            if is_danger:
                dangerous_count += 1

            details_list.append(
                AttachmentDetails(
                    filename=clean_name,
                    extension=os.path.splitext(clean_name)[1],
                    is_dangerous=is_danger,
                    has_double_extension=is_double,
                    reason=reason
                )
            )

        return AttachmentAnalysisResult(
            total_attachments=total,
            dangerous_attachments_count=dangerous_count,
            has_double_extension=has_double_ext,
            attachments=details_list,
            findings=findings
        )
