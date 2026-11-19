import os
from crewai import Agent, LLM


def get_llm() -> LLM:
    api_key = os.getenv("GROQ_API_KEY", "").strip().strip('"').strip("'")
    base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1").strip().strip('"').strip("'")
    raw_model = os.getenv("MODEL", "openai/gpt-oss-20b").strip().strip('"').strip("'")

    if not api_key:
        raise ValueError("GROQ_API_KEY missing in .env file!")

    clean_model = raw_model.removeprefix("groq/")
    if not clean_model.startswith("openai/"):
        clean_model = f"openai/{clean_model}"

    return LLM(
        model=clean_model,
        provider="openai",
        api_key=api_key,
        base_url=base_url,
        temperature=0.1,
    )


def create_security_agents() -> dict[str, Agent]:
    llm = get_llm()

    triage_agent = Agent(
        role="SOC Alert Triage Specialist",
        goal="Accurately filter false positives, assess alert severity, and decide whether deep investigation is required.",
        backstory=(
            "You are a senior Tier-1 SOC analyst experienced in separating routine monitoring noise "
            "and known benign activity from genuine cyber threats."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    log_investigator_agent = Agent(
        role="Forensic Log & Telemetry Investigator",
        goal="Investigate security logs, reconstruct timelines, and extract Indicators of Compromise (IOCs).",
        backstory=(
            "You are a digital forensics investigator skilled at correlating authentication logs, "
            "command execution traces, and network activity to uncover attacker behavior."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    threat_intel_agent = Agent(
        role="Threat Intelligence & ATT&CK Analyst",
        goal="Enrich IOCs with threat intelligence, map behaviors to MITRE ATT&CK techniques, and evaluate blast radius.",
        backstory=(
            "You specialize in adversary tradecraft, MITRE ATT&CK mapping, and assessing lateral movement "
            "and business impact across affected infrastructure."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    response_strategist_agent = Agent(
        role="Incident Response & Remediation Strategist",
        goal="Recommend clear containment, eradication, and recovery actions with proper human-approval flags.",
        backstory=(
            "You are an incident commander who turns technical findings into prioritized, safe remediation "
            "playbooks while protecting production uptime and ensuring human sign-off on disruptive actions."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    return {
        "triage": triage_agent,
        "log_investigator": log_investigator_agent,
        "threat_intel": threat_intel_agent,
        "response_strategist": response_strategist_agent,
    }