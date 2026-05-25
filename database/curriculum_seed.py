"""
Real-world style curriculum for seeded EduVibe courses.
Applied when app_meta.curriculum_version is below CURRICULUM_VERSION.
"""

import json

CURRICULUM_VERSION = "8"


def video_material(
    summary: str,
    video_url: str,
    objectives: list[str],
    outcome: str = "",
    scenario_task: str = "",
    artifacts: list[dict] | None = None,
) -> str:
    payload = {
        "format": "material_v1",
        "summary": summary,
        "video_url": video_url,
        "objectives": objectives,
    }
    if outcome:
        payload["outcome"] = outcome
    if scenario_task:
        payload["scenario_task"] = scenario_task
    if artifacts:
        payload["artifacts"] = artifacts
    return json.dumps(payload, ensure_ascii=False)


def article_material(
    summary: str,
    sections: list[dict],
    outcome: str = "",
    scenario_task: str = "",
    artifacts: list[dict] | None = None,
) -> str:
    payload = {
        "format": "material_v1",
        "summary": summary,
        "sections": sections,
    }
    if outcome:
        payload["outcome"] = outcome
    if scenario_task:
        payload["scenario_task"] = scenario_task
    if artifacts:
        payload["artifacts"] = artifacts
    return json.dumps(payload, ensure_ascii=False)


def quiz_material(
    summary: str,
    questions: list[dict],
    outcome: str = "",
    scenario_task: str = "",
    artifacts: list[dict] | None = None,
) -> str:
    payload = {
        "format": "material_v1",
        "summary": summary,
        "questions": questions,
    }
    if outcome:
        payload["outcome"] = outcome
    if scenario_task:
        payload["scenario_task"] = scenario_task
    if artifacts:
        payload["artifacts"] = artifacts
    return json.dumps(payload, ensure_ascii=False)

# title -> [ { "title": section_name, "lessons": [ { "title", "type", "minutes", "content", "preview"? }, ... ] }, ... ]
CURRICULA = {
    "Intro to SOC": [
        {
            "title": "Security Operations in Context",
            "lessons": [
                {
                    "title": "From NOC to SOC: roles, tiers, and handoffs",
                    "type": "video",
                    "minutes": 24,
                    "preview": True,
                    "content": video_material(
                        "How SOC teams are organized and how incidents move from alert to closure.",
                        "https://www.youtube.com/watch?v=Rt7hojoOIYw",
                        [
                            "Explain T1/T2/T3 responsibilities with examples.",
                            "Describe analyst handoff checkpoints in incident lifecycle.",
                            "Identify which artifacts must be captured before escalation.",
                        ],
                        outcome="Map incoming alerts to the right SOC tier and escalation owner.",
                        scenario_task="You receive a high-severity phishing alert at 02:10. Decide whether it stays in T1 or escalates to T2, and list three artifacts you must attach before handoff.",
                        artifacts=[
                            {"name": "handoff_note_template", "value": "incident_id, severity, current impact, actions_taken, next_owner"},
                            {"name": "evidence_checklist", "value": "alert_time, affected_user, host, source_ip, related_tickets"},
                        ],
                    ),
                },
                {
                    "title": "Reading a shift runbook and escalation matrix",
                    "type": "article",
                    "minutes": 18,
                    "content": article_material(
                        "How to read runbooks quickly under pressure and decide whom to page.",
                        [
                            {
                                "heading": "Severity and escalation windows",
                                "points": [
                                    "Map event attributes to severity without guessing.",
                                    "Use paging windows and fallback channels from runbook.",
                                    "Escalate to IR only after minimum evidence checklist is complete.",
                                ],
                            },
                            {
                                "heading": "Audit-ready notes",
                                "points": [
                                    "Write what was observed, not assumptions.",
                                    "Include timestamps, ticket IDs, and source system.",
                                    "Record handoff owner and expected next action.",
                                ],
                            },
                        ],
                        outcome="Use runbook rules to make consistent escalation decisions under time pressure.",
                        scenario_task="A critical auth alert fires outside primary hours. Choose paging target, urgency, and write a 3-line escalation note.",
                        artifacts=[
                            {"name": "runbook_excerpt", "value": "sev1 -> pager-primary, 5m ack, fallback incident commander"},
                            {"name": "escalation_matrix", "value": "identity-team for auth anomalies, network-team for egress spikes"},
                        ],
                    ),
                },
                {
                    "title": "Quiz: SOC terminology checkpoint",
                    "type": "quiz",
                    "minutes": 12,
                    "content": quiz_material(
                        "Check your understanding of core SOC terminology.",
                        [
                            {
                                "q": "Which metric measures average detection speed?",
                                "options": ["MTTR", "MTTD", "SLA", "CVE"],
                                "answer": "MTTD",
                                "explanation": "MTTD is mean time to detect.",
                            },
                            {
                                "q": "What best describes an incident?",
                                "options": [
                                    "Any log line",
                                    "A correlated alert with business impact or risk",
                                    "A dashboard widget",
                                    "A vulnerability CVSS score",
                                ],
                                "answer": "A correlated alert with business impact or risk",
                                "explanation": "Incidents are actionable security events with impact.",
                            },
                            {
                                "q": "A brute-force alert triggered, then auto-resolved after no repeated attempts. Most likely classification?",
                                "options": ["Confirmed breach", "Benign true positive", "Parser failure", "MTTD issue"],
                                "answer": "Benign true positive",
                                "explanation": "The detection worked and found behavior, but final risk stayed low.",
                            },
                            {
                                "q": "Which metric usually reflects containment and recovery speed?",
                                "options": ["MTTD", "MTTR", "CWE", "SLA breach ratio"],
                                "answer": "MTTR",
                                "explanation": "MTTR tracks response and remediation duration.",
                            },
                        ],
                        outcome="Differentiate event/alert/incident and interpret key SOC metrics correctly.",
                        scenario_task="Your manager asks for one KPI on detection speed and one on response speed. Pick both and justify in one sentence.",
                    ),
                },
            ],
        },
        {
            "title": "SIEM Data Flow and Log Hygiene",
            "lessons": [
                {
                    "title": "Ingestion pipelines: agents, syslog, and cloud feeds",
                    "type": "video",
                    "minutes": 28,
                    "content": video_material(
                        "Understand source-to-SIEM pipelines and common ingestion breakpoints.",
                        "https://www.youtube.com/watch?v=O5SaFwAMMtA",
                        [
                            "Trace data path from endpoint agent to SIEM index.",
                            "Spot clock-skew and parser drift symptoms.",
                            "Define first-response checks when source feed goes silent.",
                        ],
                        outcome="Troubleshoot ingestion failures using a repeatable source-to-index checklist.",
                        scenario_task="Firewall logs stop appearing for 15 minutes. Identify first 3 checkpoints and where you would verify each.",
                    ),
                },
                {
                    "title": "Normalizing fields: CEF, JSON, and custom parsers",
                    "type": "article",
                    "minutes": 22,
                    "content": article_material(
                        "Build reliable field normalization for multi-vendor telemetry.",
                        [
                            {
                                "heading": "Core mapping",
                                "points": [
                                    "Normalize source IP, user, host, action, outcome.",
                                    "Preserve raw payload for forensic backtracking.",
                                    "Tag assets with owner/team and criticality.",
                                ],
                            },
                            {
                                "heading": "Parser hygiene",
                                "points": [
                                    "Handle multiline payloads deterministically.",
                                    "Version parsers and test against fixture samples.",
                                    "Alert on parser error-rate spikes.",
                                ],
                            },
                        ],
                        outcome="Design field mappings that preserve context and support investigations.",
                        scenario_task="Map a vendor-specific auth log to common fields (user, src_ip, action, outcome) and note one ambiguity.",
                    ),
                },
                {
                    "title": "Lab walkthrough: pivoting from a single Windows Event ID",
                    "type": "video",
                    "minutes": 26,
                    "content": video_material(
                        "Start from Event ID 4688 and pivot to process tree + network telemetry.",
                        "https://www.youtube.com/watch?v=mCfkFO0xs34",
                        [
                            "Correlate process ancestry with command-line indicators.",
                            "Pivot from endpoint logs into DNS/proxy records.",
                            "Document suspicious chain in triage-ready narrative.",
                        ],
                        outcome="Pivot from one endpoint event to a broader host/network timeline.",
                    ),
                },
            ],
        },
        {
            "title": "Detection Engineering Basics",
            "lessons": [
                {
                    "title": "Use cases vs rules vs models",
                    "type": "article",
                    "minutes": 20,
                    "content": article_material(
                        "Translate business risk into maintainable detections.",
                        [
                            {
                                "heading": "Detection lifecycle",
                                "points": [
                                    "Define hypothesis and observable behavior.",
                                    "Choose batch rule vs streaming rule vs anomaly model.",
                                    "Attach owner, test plan, and rollback strategy.",
                                ],
                            }
                        ],
                        outcome="Convert use-case ideas into owned, testable detection rules.",
                    ),
                },
                {
                    "title": "Tuning noisy rules without blind spots",
                    "type": "video",
                    "minutes": 25,
                    "content": video_material(
                        "Tune noisy detections while preserving meaningful coverage.",
                        "https://www.youtube.com/watch?v=Rt7hojoOIYw",
                        [
                            "Apply threshold and context-based tuning safely.",
                            "Use allowlists with expiry and ownership metadata.",
                            "Measure before/after precision and analyst workload.",
                        ],
                        outcome="Reduce alert noise while maintaining detection intent.",
                    ),
                },
                {
                    "title": "MITRE ATT&CK as a coverage map",
                    "type": "article",
                    "minutes": 16,
                    "content": article_material(
                        "Use ATT&CK mapping to explain what you detect and what you miss.",
                        [
                            {
                                "heading": "Coverage communication",
                                "points": [
                                    "Map rules to ATT&CK techniques with confidence notes.",
                                    "Identify ransomware chain gaps by stage.",
                                    "Report coverage limits clearly to leadership.",
                                ],
                            }
                        ],
                        outcome="Report detection coverage and gaps in a clear ATT&CK-based view.",
                    ),
                },
            ],
        },
        {
            "title": "Incident Response Workflows",
            "lessons": [
                {
                    "title": "Triage checklist for suspicious authentication",
                    "type": "video",
                    "minutes": 30,
                    "content": video_material(
                        "Triage impossible-travel and MFA-fatigue patterns with a repeatable checklist.",
                        "https://www.youtube.com/watch?v=HkjoN3OCCvs",
                        [
                            "Validate identity signals and session context.",
                            "Gather mandatory evidence before user lockout.",
                            "Escalate to IR with concise timeline and risk statement.",
                        ],
                        outcome="Run consistent triage for suspicious authentication incidents.",
                    ),
                },
                {
                    "title": "Containment, eradication, and recovery in plain language",
                    "type": "article",
                    "minutes": 19,
                    "content": article_material(
                        "Align NIST response phases with day-to-day SOC ticket workflow.",
                        [
                            {
                                "heading": "Operational handoff",
                                "points": [
                                    "Define ticket state criteria for each response phase.",
                                    "Preserve evidence before containment actions.",
                                    "Use stakeholder communication templates per phase.",
                                ],
                            }
                        ],
                        outcome="Translate IR framework phases into actionable ticket states.",
                    ),
                },
                {
                    "title": "Tabletop prep: roles during a ransomware exercise",
                    "type": "quiz",
                    "minutes": 14,
                    "content": quiz_material(
                        "Scenario checkpoint for ransomware tabletop responsibilities.",
                        [
                            {
                                "q": "Who approves internet-facing containment during a live outbreak?",
                                "options": ["Any T1 analyst", "Incident commander", "Finance", "Helpdesk"],
                                "answer": "Incident commander",
                                "explanation": "Containment authority should be predefined in IR governance.",
                            },
                            {
                                "q": "When do you involve external forensics?",
                                "options": [
                                    "Only after system rebuild",
                                    "When scope/impact exceeds internal capability or legal requirements apply",
                                    "Never",
                                    "Only if backups fail",
                                ],
                                "answer": "When scope/impact exceeds internal capability or legal requirements apply",
                                "explanation": "External responders are engaged by policy and impact thresholds.",
                            },
                            {
                                "q": "Which action should happen before broad containment?",
                                "options": [
                                    "Delete all suspect logs",
                                    "Capture volatile evidence and affected scope snapshot",
                                    "Send public statement immediately",
                                    "Disable SIEM parsers",
                                ],
                                "answer": "Capture volatile evidence and affected scope snapshot",
                                "explanation": "Evidence capture prevents blind response and preserves forensic value.",
                            },
                            {
                                "q": "What is the best first communication to leadership during uncertainty?",
                                "options": [
                                    "Everything is under control, no details",
                                    "Preliminary scope, known impact, next update time",
                                    "Only technical IOC list",
                                    "Wait for final RCA",
                                ],
                                "answer": "Preliminary scope, known impact, next update time",
                                "explanation": "Leaders need concise status plus expected cadence.",
                            },
                        ],
                        outcome="Choose correct ownership and sequencing during high-pressure response.",
                    ),
                },
            ],
        },
        {
            "title": "Metrics, Reporting, and Continuous Improvement",
            "lessons": [
                {
                    "title": "Operational metrics that leadership actually reads",
                    "type": "video",
                    "minutes": 21,
                    "content": video_material(
                        "Build executive-friendly SOC reporting without vanity metrics.",
                        "https://www.youtube.com/watch?v=KfywUb7CVjw",
                        [
                            "Present queue age and backlog trends with business context.",
                            "Highlight repeated risky assets and unresolved root causes.",
                            "Recommend measurable improvements per quarter.",
                        ],
                        outcome="Prepare SOC metrics that support clear management decisions.",
                    ),
                },
                {
                    "title": "Post-incident review template",
                    "type": "article",
                    "minutes": 17,
                    "content": article_material(
                        "Reusable PIR template for SOC and stakeholder review.",
                        [
                            {
                                "heading": "Template sections",
                                "points": [
                                    "Timeline with detection and response milestones.",
                                    "Root cause and contributing control gaps.",
                                    "Action items with owner, due date, and verification step.",
                                ],
                            }
                        ],
                        outcome="Run PIR meetings with concrete follow-ups and accountable owners.",
                        scenario_task="Draft three corrective actions after an auth incident: one detection fix, one process fix, one training fix.",
                    ),
                },
            ],
        },
    ],
    "Web Pentesting Lab": [
        {
            "title": "Methodology and Safe Lab Practice",
            "lessons": [
                {
                    "title": "Rules of engagement, scope, and authorization",
                    "type": "video",
                    "minutes": 22,
                    "preview": True,
                    "content": video_material(
                        "Define legal scope before testing and avoid out-of-scope impact.",
                        "https://www.youtube.com/watch?v=kHOEKmWH9js",
                        [
                            "Differentiate authorized testing from prohibited activity.",
                            "Identify boundaries for hosts, endpoints, and time window.",
                            "Document approvals before running active scans.",
                        ],
                        outcome="Prepare a valid, auditable rules-of-engagement document.",
                        scenario_task="Client asks to test an extra staging host not listed in scope. Decide what to do before any request is sent.",
                        artifacts=[
                            {"name": "scope_sheet", "value": "targets, exclusions, allowed methods, maintenance window"},
                            {"name": "authorization_email", "value": "signed approval with date, owner, and test boundaries"},
                        ],
                    ),
                },
                {
                    "title": "Setting up Burp Suite for structured testing",
                    "type": "video",
                    "minutes": 27,
                    "content": video_material(
                        "Configure proxy tooling for repeatable and clean web assessments.",
                        "https://www.youtube.com/watch?v=IYk7-xvOMOo",
                        [
                            "Set proxy/intercept safely without breaking app auth flow.",
                            "Filter noise and keep only actionable requests.",
                            "Tag findings and requests for reproducible reports.",
                        ],
                        outcome="Build a clean project workspace that supports reliable retesting.",
                        scenario_task="Your site map has 10k static resources. Define filters to keep only dynamic attack surface endpoints.",
                    ),
                },
            ],
        },
        {
            "title": "Reconnaissance and Attack Surface",
            "lessons": [
                {
                    "title": "Passive OSINT for web targets",
                    "type": "article",
                    "minutes": 20,
                    "content": article_material(
                        "Map exposed assets using passive sources before touching the target.",
                        [
                            {
                                "heading": "Passive intelligence workflow",
                                "points": [
                                    "Use certificate transparency to enumerate subdomains.",
                                    "Review historical DNS for retired but reachable hosts.",
                                    "Extract endpoint hints from public JS bundles.",
                                ],
                            },
                            {
                                "heading": "Repo and metadata hygiene",
                                "points": [
                                    "Identify leaked internal hostnames in docs/issues.",
                                    "Capture evidence links for each discovered asset.",
                                    "Separate confirmed attack surface from assumptions.",
                                ],
                            },
                        ],
                        outcome="Produce a validated passive asset inventory for scoping.",
                        scenario_task="You find 4 subdomains in CT logs. Rank them by likely risk and justify your order.",
                    ),
                },
                {
                    "title": "Mapping endpoints and hidden parameters",
                    "type": "video",
                    "minutes": 29,
                    "content": video_material(
                        "Enumerate application endpoints and parameter attack surface systematically.",
                        "https://www.youtube.com/watch?v=IYk7-xvOMOo",
                        [
                            "Compare spidering vs dictionary-based discovery.",
                            "Use parameter discovery lists without flooding target.",
                            "Interpret 403/404 behavior as path existence signals.",
                        ],
                        outcome="Generate a prioritized endpoint map for deeper testing.",
                        scenario_task="A path returns 403 for guessed names and 404 for random strings. Explain what this suggests and next safe step.",
                    ),
                },
            ],
        },
        {
            "title": "Injection and Broken Access Control",
            "lessons": [
                {
                    "title": "SQL injection patterns from error to union",
                    "type": "video",
                    "minutes": 32,
                    "content": video_material(
                        "Understand SQL injection discovery patterns in controlled lab scenarios.",
                        "https://www.youtube.com/watch?v=ciNHn38EyRc",
                        [
                            "Spot error-based indicators and input handling flaws.",
                            "Differentiate union-based and blind validation approaches.",
                            "Document PoC safely without data overexposure.",
                        ],
                        outcome="Recognize SQLi indicators and report reproducible evidence.",
                        scenario_task="A search parameter triggers SQL syntax errors intermittently. Define three validation steps before claiming SQLi.",
                    ),
                },
                {
                    "title": "Horizontal and vertical IDOR cases",
                    "type": "article",
                    "minutes": 24,
                    "content": article_material(
                        "Test object-level authorization controls in APIs and web apps.",
                        [
                            {
                                "heading": "Horizontal vs vertical access checks",
                                "points": [
                                    "Swap object identifiers across equal-privilege users.",
                                    "Test privileged endpoints with low-privilege tokens.",
                                    "Observe server-side authorization decisions, not UI hints.",
                                ],
                            },
                            {
                                "heading": "Common implementation gaps",
                                "points": [
                                    "Missing ownership validation in API handlers.",
                                    "Mass assignment leading to role/owner override.",
                                    "JWT trust mistakes without backend claim enforcement.",
                                ],
                            },
                        ],
                        outcome="Validate authorization logic and map findings to business impact.",
                        scenario_task="Changing `/api/invoices/101` to `/api/invoices/102` returns another user's data. Write the core issue statement in one sentence.",
                    ),
                },
                {
                    "title": "Quiz: choosing the right proof-of-concept severity",
                    "type": "quiz",
                    "minutes": 15,
                    "content": quiz_material(
                        "Decide severity based on exploitability and business impact.",
                        [
                            {
                                "q": "An endpoint leaks another user's billing address with valid auth. Best severity baseline?",
                                "options": ["Low", "Medium/High depending volume", "Informational", "None"],
                                "answer": "Medium/High depending volume",
                                "explanation": "Cross-user data exposure is a real confidentiality impact.",
                            },
                            {
                                "q": "A reflected parameter echoes HTML but CSP blocks script execution. Best report framing?",
                                "options": [
                                    "Critical XSS confirmed",
                                    "Potential XSS context with mitigations in place",
                                    "Ignore entirely",
                                    "Classify as SQL injection",
                                ],
                                "answer": "Potential XSS context with mitigations in place",
                                "explanation": "Explain risk and current mitigating controls objectively.",
                            },
                            {
                                "q": "What strengthens PoC quality most?",
                                "options": ["Long exploit chain", "Reproducible minimal steps + impact evidence", "Screenshots only", "Tool output without context"],
                                "answer": "Reproducible minimal steps + impact evidence",
                                "explanation": "Clients need repeatable verification and clear impact.",
                            },
                        ],
                        outcome="Assign realistic severity and communicate findings responsibly.",
                    ),
                },
            ],
        },
        {
            "title": "XSS, CSRF, and Client-Side Issues",
            "lessons": [
                {
                    "title": "Reflected vs stored vs DOM-based XSS",
                    "type": "video",
                    "minutes": 28,
                    "content": video_material(
                        "Differentiate XSS classes and validation contexts in modern web apps.",
                        "https://www.youtube.com/watch?v=L5l9lSnNMxg",
                        [
                            "Identify source/sink pairs for reflected, stored, and DOM XSS.",
                            "Map output encoding requirements by context.",
                            "Evaluate CSP as mitigation, not silver bullet.",
                        ],
                        outcome="Classify XSS findings accurately and recommend context-specific fixes.",
                    ),
                },
                {
                    "title": "CSRF tokens, SameSite cookies, and state-changing requests",
                    "type": "article",
                    "minutes": 18,
                    "content": article_material(
                        "Assess CSRF defenses across browsers, cookies, and API patterns.",
                        [
                            {
                                "heading": "Defense layers",
                                "points": [
                                    "Validate anti-CSRF tokens on state-changing requests.",
                                    "Use SameSite + secure cookie settings intentionally.",
                                    "Require re-auth or step-up for high-risk actions.",
                                ],
                            },
                            {
                                "heading": "Pitfalls",
                                "points": [
                                    "JSON endpoints still vulnerable with implicit auth cookies.",
                                    "Double-submit cookie pattern without strict verification.",
                                    "Token checks only in frontend, missing backend enforcement.",
                                ],
                            },
                        ],
                        outcome="Verify CSRF controls beyond framework defaults.",
                    ),
                },
            ],
        },
        {
            "title": "Reporting and Remediation",
            "lessons": [
                {
                    "title": "Writing clear reproduction steps",
                    "type": "video",
                    "minutes": 23,
                    "content": video_material(
                        "Write concise, reproducible findings that developers can validate quickly.",
                        "https://www.youtube.com/watch?v=J34DnrX7dTo",
                        [
                            "Document request/response evidence and prerequisites.",
                            "Provide minimal reproduction path with expected outcome.",
                            "Tie severity to concrete business risk narrative.",
                        ],
                        outcome="Deliver report entries that reduce back-and-forth with dev teams.",
                        artifacts=[
                            {"name": "finding_template", "value": "title, affected endpoint, steps, impact, fix recommendation"},
                            {"name": "evidence_bundle", "value": "sanitized HTTP traces + screenshots + timestamp"},
                        ],
                    ),
                },
                {
                    "title": "Developer-friendly fix guidance",
                    "type": "article",
                    "minutes": 16,
                    "content": article_material(
                        "Translate security findings into patch-ready developer guidance.",
                        [
                            {
                                "heading": "Fix patterns",
                                "points": [
                                    "Use parameterized queries for all data access paths.",
                                    "Apply output encoding in the exact render context.",
                                    "Enforce authorization server-side at handler boundary.",
                                ],
                            },
                            {
                                "heading": "Validation and rollout",
                                "points": [
                                    "Add regression tests for the vulnerable flow.",
                                    "Deploy with feature flags where feasible.",
                                    "Retest and attach proof-of-fix to ticket.",
                                ],
                            },
                        ],
                        outcome="Produce remediation notes that are secure, actionable, and testable.",
                        scenario_task="Write one remediation paragraph for an IDOR finding so a backend engineer can implement it without follow-up questions.",
                    ),
                },
            ],
        },
    ],
    "Python for Analysts": [
        {
            "title": "Environment and Python Essentials",
            "lessons": [
                {
                    "title": "Virtual environments, pip, and reproducible scripts",
                    "type": "video",
                    "minutes": 20,
                    "preview": True,
                    "content": video_material(
                        "Set up clean Python environments for repeatable analyst scripts.",
                        "https://www.youtube.com/watch?v=eDe-z2Qy9x4",
                        [
                            "Create and activate isolated virtual environments.",
                            "Pin key dependencies for reproducibility.",
                            "Structure small security scripts for team reuse.",
                        ],
                        outcome="Build reproducible Python tooling on analyst workstations.",
                        scenario_task="A teammate cannot run your script due to package mismatch. Define the minimum environment handoff files.",
                    ),
                },
                {
                    "title": "Files, paths, and encoding pitfalls with logs",
                    "type": "article",
                    "minutes": 17,
                    "content": article_material(
                        "Handle log files safely across path and encoding differences.",
                        [
                            {
                                "heading": "File handling basics",
                                "points": [
                                    "Use pathlib for portable path operations.",
                                    "Stream large logs instead of reading whole file into memory.",
                                    "Guard against missing file and permission errors.",
                                ],
                            },
                            {
                                "heading": "Encoding reliability",
                                "points": [
                                    "Prefer UTF-8 with fallback strategy for mixed feeds.",
                                    "Detect and document decoding anomalies.",
                                    "Normalize line endings before parsing.",
                                ],
                            },
                        ],
                        outcome="Read heterogeneous log files without breaking parsers.",
                    ),
                },
            ],
        },
        {
            "title": "Parsing and Normalizing Log Lines",
            "lessons": [
                {
                    "title": "Regular expressions for IOC extraction",
                    "type": "video",
                    "minutes": 26,
                    "content": video_material(
                        "Extract indicators of compromise with practical regex patterns.",
                        "https://www.youtube.com/watch?v=K8L6KVGG-7o",
                        [
                            "Extract IPv4, domains, hashes and URLs from noisy text.",
                            "Avoid expensive regex patterns on long log lines.",
                            "Validate extracted indicators before enrichment.",
                        ],
                        outcome="Implement robust IOC extraction for triage automation.",
                    ),
                },
                {
                    "title": "CSV and JSON one-liners to multi-step pipelines",
                    "type": "article",
                    "minutes": 22,
                    "content": article_material(
                        "Transform mixed log formats into analyst-friendly normalized tables.",
                        [
                            {
                                "heading": "CSV and JSON parsing",
                                "points": [
                                    "Use csv.DictReader for predictable field access.",
                                    "Load nested JSON safely and flatten relevant keys.",
                                    "Normalize timestamp and hostname fields for merges.",
                                ],
                            },
                            {
                                "heading": "Pipeline design",
                                "points": [
                                    "Split extract/transform/export steps clearly.",
                                    "Add sanity checks for missing critical fields.",
                                    "Emit clean CSV output for SIEM upload or pivoting.",
                                ],
                            },
                        ],
                        outcome="Build lightweight ETL workflows for security telemetry.",
                    ),
                },
                {
                    "title": "Lab: building a small log summarizer CLI",
                    "type": "quiz",
                    "minutes": 25,
                    "content": quiz_material(
                        "Validate CLI design choices for a practical log summarizer.",
                        [
                            {
                                "q": "Which argparse option is best for selecting input file path?",
                                "options": ["--input", "--silent", "--debug", "--force"],
                                "answer": "--input",
                                "explanation": "Explicit input path flag improves script usability and automation.",
                            },
                            {
                                "q": "Most reliable key for grouping auth failures by user+host?",
                                "options": ["raw line text", "timestamp only", "user and host normalized fields", "line number"],
                                "answer": "user and host normalized fields",
                                "explanation": "Normalized dimensions produce stable aggregation.",
                            },
                            {
                                "q": "Best way to prevent memory issues on huge logs?",
                                "options": ["Read all lines into list", "Iterate line-by-line generator", "Use recursion", "Skip error handling"],
                                "answer": "Iterate line-by-line generator",
                                "explanation": "Streaming avoids large memory spikes.",
                            },
                        ],
                        outcome="Make practical implementation decisions for analyst CLI tools.",
                    ),
                },
            ],
        },
        {
            "title": "APIs and Automation",
            "lessons": [
                {
                    "title": "requests session objects, retries, and rate limits",
                    "type": "video",
                    "minutes": 24,
                    "content": video_material(
                        "Call security APIs reliably with retries, sessions, and backoff.",
                        "https://www.youtube.com/watch?v=tb8gHvYlCFs",
                        [
                            "Reuse session connections for stable API calls.",
                            "Handle 429/5xx responses with bounded retry logic.",
                            "Store secrets outside source code.",
                        ],
                        outcome="Automate enrichment tasks without overloading APIs.",
                        artifacts=[
                            {"name": "requests_retry_snippet", "value": "session + retry adapter + timeout defaults"},
                        ],
                    ),
                },
                {
                    "title": "Scheduling with cron and Windows Task Scheduler",
                    "type": "article",
                    "minutes": 14,
                    "content": article_material(
                        "Schedule recurring security scripts safely across OS platforms.",
                        [
                            {
                                "heading": "Scheduling basics",
                                "points": [
                                    "Use absolute paths for interpreter and script.",
                                    "Log stdout/stderr to rotating files.",
                                    "Set predictable runtime windows to avoid overlap.",
                                ],
                            },
                            {
                                "heading": "Operational safety",
                                "points": [
                                    "Make jobs idempotent for reruns.",
                                    "Alert on repeated failures.",
                                    "Document owner and escalation path for automation jobs.",
                                ],
                            },
                        ],
                        outcome="Run automated tasks consistently in operational environments.",
                    ),
                },
            ],
        },
        {
            "title": "Visualization and Handoff",
            "lessons": [
                {
                    "title": "Quick charts with matplotlib for leadership summaries",
                    "type": "video",
                    "minutes": 21,
                    "content": video_material(
                        "Create simple, readable charts for SOC leadership updates.",
                        "https://www.youtube.com/watch?v=3Xc3CA655Y4",
                        [
                            "Choose chart types aligned with security KPIs.",
                            "Reduce visual clutter and keep labels actionable.",
                            "Export reproducible visuals for incident reports.",
                        ],
                        outcome="Present technical data in leadership-friendly format.",
                    ),
                },
            ],
        },
    ],
    "English for IT Communication": [
        {
            "title": "Professional Foundations",
            "lessons": [
                {
                    "title": "Clarity over jargon: explaining incidents to mixed audiences",
                    "type": "video",
                    "minutes": 23,
                    "preview": True,
                    "content": video_material(
                        "Communicate incidents clearly to technical and non-technical stakeholders.",
                        "https://www.youtube.com/watch?v=KfywUb7CVjw",
                        [
                            "Lead with impact before technical root details.",
                            "Adjust wording for executives, legal, and engineers.",
                            "Use plain language without losing precision.",
                        ],
                        outcome="Deliver incident updates that all stakeholders understand.",
                        scenario_task="Write a two-sentence update for leadership after a phishing incident without using SOC jargon.",
                    ),
                },
                {
                    "title": "Email structure for status updates and escalations",
                    "type": "article",
                    "minutes": 18,
                    "content": article_material(
                        "Use a consistent email template for security status and escalation.",
                        [
                            {
                                "heading": "Core email structure",
                                "points": [
                                    "Subject line with incident ID + status.",
                                    "Current impact and what changed since last update.",
                                    "Explicit ask and response deadline.",
                                ],
                            },
                            {
                                "heading": "Escalation quality",
                                "points": [
                                    "State owner and fallback contact clearly.",
                                    "Include links to logs/tickets instead of long paste.",
                                    "Close with next update time.",
                                ],
                            },
                        ],
                        outcome="Send concise updates that trigger the right action quickly.",
                    ),
                },
            ],
        },
        {
            "title": "Meetings and Standups",
            "lessons": [
                {
                    "title": "Running a concise incident bridge in English",
                    "type": "video",
                    "minutes": 26,
                    "content": video_material(
                        "Facilitate incident calls with clear pacing and ownership language.",
                        "https://www.youtube.com/watch?v=PCbtJ-GudLk",
                        [
                            "Open bridge calls with scope and role confirmation.",
                            "Assign action items with owner and due time.",
                            "Time-box deep dives to keep call effective.",
                        ],
                        outcome="Run bridge calls that stay focused and actionable.",
                    ),
                },
                {
                    "title": "Polite pushback and negotiating deadlines",
                    "type": "article",
                    "minutes": 16,
                    "content": article_material(
                        "Push back professionally when requests increase risk or break capacity.",
                        [
                            {
                                "heading": "Constructive pushback",
                                "points": [
                                    "Acknowledge request and explain constraint clearly.",
                                    "Offer safe alternatives with trade-offs.",
                                    "Confirm revised timeline in writing.",
                                ],
                            },
                            {
                                "heading": "Escalation language",
                                "points": [
                                    "Escalate risks without blaming teams.",
                                    "Use neutral wording for decision records.",
                                    "Capture decisions and owners in ticket trail.",
                                ],
                            },
                        ],
                        outcome="Negotiate deadlines while preserving collaboration.",
                    ),
                },
            ],
        },
        {
            "title": "Documentation and Ticketing",
            "lessons": [
                {
                    "title": "Writing defensible ticket narratives",
                    "type": "video",
                    "minutes": 22,
                    "content": video_material(
                        "Write incident tickets that are clear, defensible, and audit-ready.",
                        "https://www.youtube.com/watch?v=ibUGNc2wifQ",
                        [
                            "Separate observation from hypothesis in ticket text.",
                            "Link evidence directly to conclusions.",
                            "Document closure rationale and residual risk.",
                        ],
                        outcome="Produce ticket narratives usable by audit, IR, and engineering teams.",
                    ),
                },
                {
                    "title": "Knowledge base articles engineers will actually use",
                    "type": "article",
                    "minutes": 19,
                    "content": article_material(
                        "Structure KB entries for fast retrieval and reliable implementation.",
                        [
                            {
                                "heading": "KB design",
                                "points": [
                                    "Use searchable titles and clear prerequisites.",
                                    "Add step-by-step procedure with validation checks.",
                                    "Include rollback and escalation references.",
                                ],
                            },
                            {
                                "heading": "Maintenance",
                                "points": [
                                    "Version with last-reviewed date.",
                                    "Assign owner for periodic updates.",
                                    "Retire stale guides proactively.",
                                ],
                            },
                        ],
                        outcome="Create KB documents that teams reuse in real incidents.",
                    ),
                },
            ],
        },
        {
            "title": "Presentations and Peer Review",
            "lessons": [
                {
                    "title": "Five-slide postmortem deck pattern",
                    "type": "video",
                    "minutes": 20,
                    "content": video_material(
                        "Build concise postmortem decks for cross-functional review.",
                        "https://www.youtube.com/watch?v=y-wrnN-gtkQ",
                        [
                            "Tell timeline and impact in one clear narrative.",
                            "Highlight root cause and contributing factors.",
                            "Present action items with ownership and deadline.",
                        ],
                        outcome="Deliver postmortems that drive clear corrective action.",
                    ),
                },
                {
                    "title": "Quiz: tone and formality in stakeholder messages",
                    "type": "quiz",
                    "minutes": 12,
                    "content": quiz_material(
                        "Choose appropriate tone and formality for security communication.",
                        [
                            {
                                "q": "Best opening for executive outage update?",
                                "options": [
                                    "We have many technical details to review first",
                                    "Current impact, affected services, and next update time",
                                    "Developers are still investigating, no summary",
                                    "SOC is handling everything",
                                ],
                                "answer": "Current impact, affected services, and next update time",
                                "explanation": "Leaders need concise impact + cadence first.",
                            },
                            {
                                "q": "Which phrasing is best for blameless postmortem?",
                                "options": [
                                    "Team X failed to monitor logs",
                                    "Monitoring gap delayed detection by 40 minutes",
                                    "Nobody cared enough",
                                    "Engineers ignored security",
                                ],
                                "answer": "Monitoring gap delayed detection by 40 minutes",
                                "explanation": "Focus on systems/process, not personal blame.",
                            },
                        ],
                        outcome="Apply audience-appropriate language across incident communications.",
                    ),
                },
            ],
        },
    ],
    "German for Beginners in Tech": [
        {
            "title": "Grundlagen und Alltag im Team",
            "lessons": [
                {
                    "title": "Begrüßungen, Du/Sie, und kurze Selbstvorstellung in der IT",
                    "type": "video",
                    "minutes": 21,
                    "preview": True,
                    "content": video_material(
                        "Grundlagen für höfliche Kommunikation im deutschsprachigen Tech-Team.",
                        "https://www.youtube.com/watch?v=m92hzkGKBTs",
                        [
                            "Du/Sie in beruflichen Situationen korrekt einsetzen.",
                            "Kurze IT-Selbstvorstellung klar strukturieren.",
                            "Typische Begrüßungs- und Abschlussformeln anwenden.",
                        ],
                        outcome="Sich professionell in Team- und Meeting-Kontexten vorstellen.",
                    ),
                },
                {
                    "title": "Kalender, Meetings und Statusupdates auf Deutsch",
                    "type": "article",
                    "minutes": 18,
                    "content": article_material(
                        "Nützliche Formulierungen für Planung und kurze Statuskommunikation.",
                        [
                            {
                                "heading": "Meeting-Kommunikation",
                                "points": [
                                    "Terminvorschläge klar und höflich formulieren.",
                                    "Zu-/Absagen professionell bestätigen.",
                                    "Kurze Statusupdates mit Aktion und Frist geben.",
                                ],
                            },
                            {
                                "heading": "Alltagsphrasen",
                                "points": [
                                    "Verständnisfragen präzise stellen.",
                                    "Blocker kurz benennen und Hilfe anfragen.",
                                    "Follow-up schriftlich zusammenfassen.",
                                ],
                            },
                        ],
                        outcome="An Meetings auf Deutsch strukturiert teilnehmen.",
                    ),
                },
            ],
        },
        {
            "title": "Hardware, Software und Ticketsysteme",
            "lessons": [
                {
                    "title": "Vokabeln: Rechner, Netzwerk, Passwort, Berechtigung",
                    "type": "video",
                    "minutes": 24,
                    "content": video_material(
                        "Zentrale IT-Support- und Security-Begriffe sicher verwenden.",
                        "https://www.youtube.com/watch?v=T8c00GENYZo",
                        [
                            "Kernvokabular für Konten, Rechte und Netzwerk verstehen.",
                            "Zwischen Störung, Warnung und Sicherheitsvorfall unterscheiden.",
                            "Begriffe im Ticketsystem korrekt einsetzen.",
                        ],
                        outcome="Technische Supportfälle auf Deutsch präzise beschreiben.",
                    ),
                },
                {
                    "title": "Ein Ticket schreiben: Problem, Schritte, Dringlichkeit",
                    "type": "article",
                    "minutes": 20,
                    "content": article_material(
                        "Praktische Struktur für verständliche Tickets im IT-Kontext.",
                        [
                            {
                                "heading": "Ticket-Aufbau",
                                "points": [
                                    "Problem in einem Satz zusammenfassen.",
                                    "Reproduktionsschritte nummeriert notieren.",
                                    "Dringlichkeit mit Auswirkung begründen.",
                                ],
                            },
                            {
                                "heading": "Qualitätssicherung",
                                "points": [
                                    "Screenshots/Logs als Nachweis anhängen.",
                                    "System, Version und Zeitstempel angeben.",
                                    "Erwartetes vs tatsächliches Verhalten trennen.",
                                ],
                            },
                        ],
                        outcome="Vollständige, schnell bearbeitbare Tickets auf Deutsch erstellen.",
                    ),
                },
            ],
        },
        {
            "title": "Cybersicherheit auf Deutsch",
            "lessons": [
                {
                    "title": "Phishing, Malware, und Meldewege an die SOC",
                    "type": "video",
                    "minutes": 26,
                    "content": video_material(
                        "Sicherheitsvorfälle im Arbeitsalltag erkennen und korrekt melden.",
                        "https://www.youtube.com/watch?v=c1aPNfCPjyo",
                        [
                            "Typische Phishing-Merkmale benennen.",
                            "Sofortmaßnahmen bei verdächtigen E-Mails einleiten.",
                            "Meldung an SOC/Helpdesk strukturiert formulieren.",
                        ],
                        outcome="Verdächtige Vorfälle sicher identifizieren und eskalieren.",
                    ),
                },
                {
                    "title": "Quiz: IT- und Security-Begriffe (A1–A2)",
                    "type": "quiz",
                    "minutes": 14,
                    "content": quiz_material(
                        "Grundbegriffe der IT-Sicherheit im deutschen Sprachkontext festigen.",
                        [
                            {
                                "q": "Welche Bedeutung passt am besten zu 'Sicherheitslücke'?",
                                "options": ["Backup-Plan", "Schwachstelle im System", "Firewall-Regel", "Passwortrichtlinie"],
                                "answer": "Schwachstelle im System",
                                "explanation": "Eine Sicherheitslücke ist eine ausnutzbare Schwachstelle.",
                            },
                            {
                                "q": "Was ist der passendste erste Schritt bei verdächtigem Anhang?",
                                "options": ["Öffnen und prüfen", "An SOC/IT melden und nicht öffnen", "Weiterleiten an Kollegen", "Ignorieren"],
                                "answer": "An SOC/IT melden und nicht öffnen",
                                "explanation": "Melden ohne Öffnen reduziert Risiko und erhält Beweise.",
                            },
                        ],
                        outcome="Sicherheitsbegriffe verstehen und korrekt anwenden.",
                    ),
                },
            ],
        },
        {
            "title": "Bewerbung und Studium in Deutschland",
            "lessons": [
                {
                    "title": "Lebenslauf und Anschreiben für Tech-Rollen",
                    "type": "article",
                    "minutes": 22,
                    "content": article_material(
                        "Bewerbungsunterlagen für IT-Rollen klar und professionell strukturieren.",
                        [
                            {
                                "heading": "Lebenslauf",
                                "points": [
                                    "Technische Skills nach Relevanz ordnen.",
                                    "Projekte mit Ergebnis und Rolle beschreiben.",
                                    "Zertifikate und Sprachlevel transparent angeben.",
                                ],
                            },
                            {
                                "heading": "Anschreiben",
                                "points": [
                                    "Motivation mit Bezug zur Stelle formulieren.",
                                    "Praxisbezug durch konkrete Beispiele zeigen.",
                                    "Professionellen Abschluss mit Verfügbarkeit ergänzen.",
                                ],
                            },
                        ],
                        outcome="Aussagekräftige Bewerbungsunterlagen für Tech-Jobs erstellen.",
                    ),
                },
                {
                    "title": "Vorbereitung auf das Vorstellungsgespräch",
                    "type": "video",
                    "minutes": 19,
                    "content": video_material(
                        "Typische Interviewfragen im IT-Bereich auf Deutsch sicher beantworten.",
                        "https://www.youtube.com/watch?v=npnXAsiq3Q4",
                        [
                            "Selbstvorstellung klar und zeitlich strukturiert halten.",
                            "Technische Erfahrung verständlich erklären.",
                            "Rückfragen zu Team, Tooling und Lernpfad formulieren.",
                        ],
                        outcome="Selbstsicher in deutschsprachige Tech-Interviews gehen.",
                        scenario_task="Bereite eine 60-Sekunden-Selbstvorstellung für eine Junior-SOC-Position auf Deutsch vor.",
                    ),
                },
            ],
        },
    ],
}


def apply_full_curriculum(cur, now_iso: str) -> None:
    """Replace sections/lessons for all courses listed in CURRICULA. Clears related progress and lesson uploads."""
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    row = cur.execute(
        "SELECT value FROM app_meta WHERE key = ?",
        ("curriculum_version",),
    ).fetchone()
    if row and row[0] == CURRICULUM_VERSION:
        return

    for title, sections in CURRICULA.items():
        course_row = cur.execute("SELECT id FROM courses WHERE title = ?", (title,)).fetchone()
        if not course_row:
            continue
        course_id = course_row[0]

        cur.execute(
            "DELETE FROM uploads WHERE lesson_id IN (SELECT id FROM course_lessons WHERE course_id = ?)",
            (course_id,),
        )
        cur.execute("DELETE FROM lesson_progress WHERE course_id = ?", (course_id,))
        cur.execute("DELETE FROM course_lessons WHERE course_id = ?", (course_id,))
        cur.execute("DELETE FROM course_sections WHERE course_id = ?", (course_id,))

        for sec_pos, section in enumerate(sections, start=1):
            cur.execute(
                """
                INSERT INTO course_sections (course_id, title, position, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (course_id, section["title"], sec_pos, now_iso),
            )
            section_id = cur.lastrowid
            for les_pos, lesson in enumerate(section["lessons"], start=1):
                preview = 1 if lesson.get("preview") else 0
                cur.execute(
                    """
                    INSERT INTO course_lessons (
                        course_id, section_id, title, lesson_type, content, position,
                        is_preview, created_at, duration_minutes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        course_id,
                        section_id,
                        lesson["title"],
                        lesson["type"],
                        lesson.get("content", ""),
                        les_pos,
                        preview,
                        now_iso,
                        int(lesson.get("minutes", 20)),
                    ),
                )

    cur.execute(
        """
        INSERT INTO app_meta (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        ("curriculum_version", CURRICULUM_VERSION),
    )


def ensure_minimal_outline(cur, now_iso: str) -> None:
    """If a course has no sections (e.g. admin-created), add a single placeholder section."""
    for row in cur.execute("SELECT id, title FROM courses"):
        cid = row[0]
        title = row[1]
        if title in CURRICULA:
            continue
        exists = cur.execute(
            "SELECT 1 FROM course_sections WHERE course_id = ? LIMIT 1",
            (cid,),
        ).fetchone()
        if exists:
            continue
        cur.execute(
            """
            INSERT INTO course_sections (course_id, title, position, created_at)
            VALUES (?, ?, 1, ?)
            """,
            (cid, "Course outline", now_iso),
        )
        sid = cur.lastrowid
        cur.execute(
            """
            INSERT INTO course_lessons (
                course_id, section_id, title, lesson_type, content, position,
                is_preview, created_at, duration_minutes
            )
            VALUES (?, ?, ?, 'article', ?, 1, 1, ?, 15)
            """,
            (
                cid,
                sid,
                "Instructor will publish detailed lessons",
                "This course has no automated outline yet. Use the admin curriculum tools to add sections and lessons.",
                now_iso,
            ),
        )
