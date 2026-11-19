import json
import sys
from pathlib import Path
from crewai import Crew, Process, Task
from crewai.flow.flow import Flow, listen, router, start
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from agents.security_agents import create_security_agents
from schemas.incident_models import (
    IncidentReport,
    LogFindings,
    RawAlertInput,
    ResponsePlan,
    ThreatIntelResult,
    TriageResult,
)
from tools.security_tools import lookup_threat_intel, search_security_logs


class IncidentFlowState(BaseModel):
    alert: RawAlertInput | None = None
    triage: TriageResult | None = None
    logs: LogFindings | None = None
    threat_intel: ThreatIntelResult | None = None
    response_plan: ResponsePlan | None = None
    final_report: IncidentReport | None = None


class CybersecurityIncidentFlow(Flow[IncidentFlowState]):
    def __init__(self, alert_data: RawAlertInput, **kwargs):
        super().__init__(**kwargs)
        self.state.alert = alert_data
        self.agents = create_security_agents()

    @start()
    def triage_alert(self) -> TriageResult:
        alert = self.state.alert
        triage_task = Task(
            description=(
                f"Analyze this security alert and determine if it is a false positive or a real threat:\n"
                f"{alert.model_dump_json(indent=2)}\n"
                f"Use 'Search Security Logs' if checking context helps confirm benign or suspicious behavior."
            ),
            expected_output="Structured TriageResult with is_false_positive, severity, confidence, and reasoning.",
            agent=self.agents["triage"],
            tools=[search_security_logs],
            output_pydantic=TriageResult,
        )

        crew = Crew(
            agents=[self.agents["triage"]],
            tasks=[triage_task],
            process=Process.sequential,
            verbose=False,
        )
        result = crew.kickoff()
        triage_data: TriageResult = result.pydantic
        self.state.triage = triage_data
        return triage_data

    @router(triage_alert)
    def route_after_triage(self) -> str:
        if self.state.triage and self.state.triage.is_false_positive:
            return "false_positive"
        return "investigate_threat"

    @listen("false_positive")
    def handle_false_positive(self) -> IncidentReport:
        report = IncidentReport(
            alert_id=self.state.alert.alert_id,
            status="RESOLVED_FALSE_POSITIVE",
            triage=self.state.triage,
        )
        self.state.final_report = report
        return report

    @listen("investigate_threat")
    def run_full_investigation(self) -> IncidentReport:
        alert_json = self.state.alert.model_dump_json(indent=2)
        triage_json = self.state.triage.model_dump_json(indent=2)

        log_task = Task(
            description=(
                f"Investigate security logs for this alert and triage output:\n"
                f"Alert:\n{alert_json}\n\nTriage:\n{triage_json}\n"
                f"Query relevant IPs, hosts, or users using 'Search Security Logs'."
            ),
            expected_output="Structured LogFindings with timeline, extracted_iocs, and key_observations.",
            agent=self.agents["log_investigator"],
            tools=[search_security_logs],
            output_pydantic=LogFindings,
        )

        intel_task = Task(
            description=(
                f"Enrich extracted IOCs and alert indicators using 'Lookup Threat Intelligence'. "
                f"Identify threat category, MITRE ATT&CK techniques, and blast radius."
            ),
            expected_output="Structured ThreatIntelResult with threat_category, mitre_techniques, blast_radius, and intel_notes.",
            agent=self.agents["threat_intel"],
            tools=[lookup_threat_intel],
            context=[log_task],
            output_pydantic=ThreatIntelResult,
        )

        response_task = Task(
            description=(
                f"Based on the alert, triage, forensic log findings, and threat intelligence, "
                f"create an actionable incident response plan. Mark requires_human_approval=True "
                f"for high-impact actions like isolating production hosts or disabling active accounts."
            ),
            expected_output="Structured ResponsePlan with immediate_actions, requires_human_approval, priority_level, and executive_summary.",
            agent=self.agents["response_strategist"],
            context=[log_task, intel_task],
            output_pydantic=ResponsePlan,
        )

        investigation_crew = Crew(
            agents=[
                self.agents["log_investigator"],
                self.agents["threat_intel"],
                self.agents["response_strategist"],
            ],
            tasks=[log_task, intel_task, response_task],
            process=Process.sequential,
            verbose=False,
        )

        investigation_crew.kickoff()

        self.state.logs = log_task.output.pydantic
        self.state.threat_intel = intel_task.output.pydantic
        self.state.response_plan = response_task.output.pydantic

        report = IncidentReport(
            alert_id=self.state.alert.alert_id,
            status="INVESTIGATED_ACTION_REQUIRED",
            triage=self.state.triage,
            logs=self.state.logs,
            threat_intel=self.state.threat_intel,
            response_plan=self.state.response_plan,
        )
        self.state.final_report = report
        return report


def run_incident_investigation(alert: RawAlertInput) -> dict:
    flow = CybersecurityIncidentFlow(alert_data=alert)
    flow.kickoff()
    if flow.state.final_report:
        return json.loads(flow.state.final_report.model_dump_json())
    raise RuntimeError("Flow completed without producing a final_report.")