from typing import List, Literal
from pydantic import BaseModel, Field


class RawAlertInput(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier")
    source: str = Field(..., description="SIEM / EDR / Firewall / Cloud source")
    timestamp: str = Field(..., description="ISO timestamp of alert")
    summary: str = Field(..., description="Short description of suspicious activity")
    source_ip: str | None = Field(default=None, description="Originating IP address")
    target_user: str | None = Field(default=None, description="Affected username or service account")
    target_host: str | None = Field(default=None, description="Affected server or workstation")


class TriageResult(BaseModel):
    is_false_positive: bool = Field(..., description="True if benign/false positive")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str = Field(..., description="Why this triage decision was made")


class LogFindings(BaseModel):
    timeline: List[str] = Field(default_factory=list, description="Chronological event findings")
    extracted_iocs: List[str] = Field(default_factory=list, description="Suspicious IPs, domains, hashes, users")
    key_observations: str = Field(..., description="Summary of forensic log analysis")


class ThreatIntelResult(BaseModel):
    threat_category: str = Field(..., description="e.g., Brute Force, C2 Beaconing, Data Exfiltration, Benign")
    mitre_techniques: List[str] = Field(default_factory=list, description="e.g., T1110, T1071")
    blast_radius: str = Field(..., description="Affected hosts, accounts, or data scope")
    intel_notes: str = Field(..., description="Threat intelligence enrichment summary")


class ResponsePlan(BaseModel):
    immediate_actions: List[str] = Field(default_factory=list, description="Containment and eradication steps")
    requires_human_approval: bool = Field(..., description="True for high-impact actions like host isolation")
    priority_level: Literal["P1", "P2", "P3", "P4"] = Field(...)
    executive_summary: str = Field(..., description="Clear summary for SOC analyst")


class IncidentReport(BaseModel):
    alert_id: str
    status: Literal["RESOLVED_FALSE_POSITIVE", "INVESTIGATED_ACTION_REQUIRED"]
    triage: TriageResult
    logs: LogFindings | None = None
    threat_intel: ThreatIntelResult | None = None
    response_plan: ResponsePlan | None = None