# Lab 12: Purple Team Simulation - Solution Walkthrough

## Overview

Build an AI-powered purple team simulation framework for safe adversary emulation and detection validation.

**Time:** 4-5 hours
**Difficulty:** Advanced

---

## Task 1: Attack Simulation Framework

### Building Safe Adversary Emulation

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable
import subprocess
import json

class AttackPhase(Enum):
    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class MitreAttackTechnique:
    technique_id: str
    name: str
    tactic: AttackPhase
    description: str
    platforms: list[str]
    detection_sources: list[str]

@dataclass
class SimulationResult:
    technique_id: str
    success: bool
    execution_time: float
    artifacts_created: list[str]
    logs_generated: list[str]
    cleanup_performed: bool
    error: Optional[str] = None

class AttackSimulator:
    def __init__(self, safe_mode: bool = True):
        self.safe_mode = safe_mode
        self.techniques: dict[str, MitreAttackTechnique] = {}
        self.simulations: dict[str, Callable] = {}
        self.results: list[SimulationResult] = []

        self._load_techniques()
        self._register_simulations()

    def _load_techniques(self):
        """Load MITRE ATT&CK techniques."""
        techniques = [
            MitreAttackTechnique(
                "T1059.001", "PowerShell",
                AttackPhase.EXECUTION,
                "Adversaries may abuse PowerShell for execution",
                ["Windows"],
                ["Process monitoring", "Script block logging", "Module logging"]
            ),
            MitreAttackTechnique(
                "T1053.005", "Scheduled Task",
                AttackPhase.PERSISTENCE,
                "Adversaries may abuse scheduled tasks for persistence",
                ["Windows"],
                ["Windows Event Log", "Process monitoring"]
            ),
            MitreAttackTechnique(
                "T1003.001", "LSASS Memory",
                AttackPhase.CREDENTIAL_ACCESS,
                "Adversaries may access LSASS memory for credentials",
                ["Windows"],
                ["Process monitoring", "Sysmon"]
            ),
            MitreAttackTechnique(
                "T1087.001", "Local Account",
                AttackPhase.DISCOVERY,
                "Adversaries may enumerate local accounts",
                ["Windows", "Linux", "macOS"],
                ["Process monitoring", "Command-line logging"]
            ),
            MitreAttackTechnique(
                "T1021.001", "Remote Desktop Protocol",
                AttackPhase.LATERAL_MOVEMENT,
                "Adversaries may use RDP for lateral movement",
                ["Windows"],
                ["Authentication logs", "Network monitoring"]
            )
        ]

        for tech in techniques:
            self.techniques[tech.technique_id] = tech

    def _register_simulations(self):
        """Register safe simulation functions."""

        # T1059.001 - PowerShell execution (safe)
        def simulate_powershell():
            if self.safe_mode:
                # Safe simulation - just creates log entry
                cmd = 'powershell.exe -Command "Write-Host \'Purple Team Test\'"'
                return {
                    'command': cmd,
                    'simulated': True,
                    'artifacts': ['PowerShell script block log entry']
                }
            else:
                result = subprocess.run(
                    ['powershell', '-Command', 'Write-Host "Purple Team Test"'],
                    capture_output=True, text=True, timeout=30
                )
                return {
                    'command': 'powershell -Command "Write-Host \'Purple Team Test\'"',
                    'stdout': result.stdout,
                    'artifacts': ['Process creation event', 'Script block log']
                }

        self.simulations['T1059.001'] = simulate_powershell

        # T1087.001 - Local account discovery (safe)
        def simulate_account_discovery():
            if self.safe_mode:
                return {
                    'command': 'net user (simulated)',
                    'simulated': True,
                    'artifacts': ['Process creation event for net.exe']
                }
            else:
                result = subprocess.run(
                    ['net', 'user'],
                    capture_output=True, text=True, timeout=30
                )
                return {
                    'command': 'net user',
                    'stdout': result.stdout,
                    'artifacts': ['Process creation event']
                }

        self.simulations['T1087.001'] = simulate_account_discovery

        # T1053.005 - Scheduled task (safe - creates then removes)
        def simulate_scheduled_task():
            task_name = f"PurpleTeamTest_{datetime.now().strftime('%Y%m%d%H%M%S')}"

            if self.safe_mode:
                return {
                    'command': f'schtasks /create /tn {task_name} (simulated)',
                    'simulated': True,
                    'artifacts': ['Task Scheduler event log entry']
                }
            else:
                # Create task
                create_result = subprocess.run([
                    'schtasks', '/create', '/tn', task_name,
                    '/tr', 'cmd.exe /c echo test',
                    '/sc', 'once', '/st', '23:59'
                ], capture_output=True, text=True)

                # Immediately delete
                delete_result = subprocess.run([
                    'schtasks', '/delete', '/tn', task_name, '/f'
                ], capture_output=True, text=True)

                return {
                    'task_name': task_name,
                    'created': create_result.returncode == 0,
                    'deleted': delete_result.returncode == 0,
                    'artifacts': ['Task Scheduler creation event', 'Task Scheduler deletion event']
                }

        self.simulations['T1053.005'] = simulate_scheduled_task

    def execute_technique(self, technique_id: str) -> SimulationResult:
        """Execute a single attack technique simulation."""

        if technique_id not in self.techniques:
            return SimulationResult(
                technique_id=technique_id,
                success=False,
                execution_time=0,
                artifacts_created=[],
                logs_generated=[],
                cleanup_performed=False,
                error=f"Unknown technique: {technique_id}"
            )

        technique = self.techniques[technique_id]

        if technique_id not in self.simulations:
            return SimulationResult(
                technique_id=technique_id,
                success=False,
                execution_time=0,
                artifacts_created=[],
                logs_generated=[],
                cleanup_performed=False,
                error=f"No simulation available for: {technique_id}"
            )

        start_time = datetime.now()

        try:
            result = self.simulations[technique_id]()
            execution_time = (datetime.now() - start_time).total_seconds()

            sim_result = SimulationResult(
                technique_id=technique_id,
                success=True,
                execution_time=execution_time,
                artifacts_created=result.get('artifacts', []),
                logs_generated=technique.detection_sources,
                cleanup_performed=True
            )

        except Exception as e:
            sim_result = SimulationResult(
                technique_id=technique_id,
                success=False,
                execution_time=(datetime.now() - start_time).total_seconds(),
                artifacts_created=[],
                logs_generated=[],
                cleanup_performed=False,
                error=str(e)
            )

        self.results.append(sim_result)
        return sim_result

# Initialize simulator
simulator = AttackSimulator(safe_mode=True)

# Execute simulation
result = simulator.execute_technique("T1059.001")
print(f"Technique: {result.technique_id}")
print(f"Success: {result.success}")
print(f"Artifacts: {result.artifacts_created}")
```

---

## Task 2: Detection Validation

### Validating Security Controls

```python
import anthropic

class DetectionValidator:
    def __init__(self, siem_client=None, siem_type: str = "auto"):
        """
        Initialize detection validator.

        Args:
            siem_client: Optional SIEM client (Splunk, Elastic, Sentinel, etc.)
            siem_type: SIEM platform type - "splunk", "elastic", "sentinel", or "auto"

        Note: SIEM integration is optional. The validator works in simulation
        mode without a SIEM client for testing and development.
        """
        self.siem_client = siem_client
        self.siem_type = siem_type
        self.client = anthropic.Anthropic()
        self.validation_results = []

    def generate_detection_query(self, technique: MitreAttackTechnique) -> dict:
        """Generate detection queries for a technique."""

        prompt = f"""Generate detection queries for MITRE ATT&CK technique:

Technique ID: {technique.technique_id}
Name: {technique.name}
Tactic: {technique.tactic.value}
Description: {technique.description}
Detection Sources: {technique.detection_sources}

Generate detection queries for these platforms (in order of preference):
1. Splunk (SPL)
2. Elastic (EQL/KQL)
3. Microsoft Sentinel (KQL)
4. Sigma rule (platform-agnostic)

Return JSON with keys: splunk_query, elastic_query, sentinel_query, sigma_rule"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            queries = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            queries = {'raw': response.content[0].text}

        return queries

    def validate_detection(self, technique_id: str,
                          simulation_time: datetime,
                          time_window_minutes: int = 5) -> dict:
        """Validate if simulation was detected."""

        # Query SIEM for alerts in time window
        # This would integrate with actual SIEM

        validation = {
            'technique_id': technique_id,
            'simulation_time': simulation_time.isoformat(),
            'time_window': f"{time_window_minutes} minutes",
            'detected': False,
            'alerts_found': [],
            'detection_gap': None
        }

        # Simulated validation (in production, query SIEM)
        if self.siem_client:
            # Example Splunk query
            query = f'''
                index=security sourcetype=*
                earliest="{simulation_time.strftime('%m/%d/%Y:%H:%M:%S')}"
                latest="+{time_window_minutes}m"
                | search mitre_attack_id="{technique_id}"
            '''
            # results = self.siem_client.search(query)
            # validation['detected'] = len(results) > 0
            # validation['alerts_found'] = results

        return validation

    def analyze_detection_gap(self, technique: MitreAttackTechnique,
                             validation_result: dict) -> str:
        """Analyze why detection might have failed."""

        prompt = f"""A purple team simulation was executed but not detected. Analyze the detection gap:

## Technique
- ID: {technique.technique_id}
- Name: {technique.name}
- Tactic: {technique.tactic.value}
- Expected Detection Sources: {technique.detection_sources}

## Validation Result
- Detected: {validation_result['detected']}
- Time Window: {validation_result['time_window']}
- Alerts Found: {validation_result['alerts_found']}

Provide:
1. Likely reasons for detection gap
2. Recommended detection improvements
3. Logging requirements to fill the gap
4. Sample detection rules that should catch this"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Validate detections
validator = DetectionValidator()

# Generate detection queries
technique = simulator.techniques["T1059.001"]
queries = validator.generate_detection_query(technique)
print("Detection Queries:")
print(json.dumps(queries, indent=2))
```

---

## Task 3: Campaign Simulation

### Multi-Stage Attack Campaigns

```python
@dataclass
class AttackCampaign:
    name: str
    description: str
    threat_actor: str
    techniques: list[str]  # Ordered list of technique IDs
    success_criteria: dict

class CampaignSimulator:
    def __init__(self, attack_simulator: AttackSimulator):
        self.simulator = attack_simulator
        self.campaigns: dict[str, AttackCampaign] = {}
        self._load_campaigns()

    def _load_campaigns(self):
        """Load predefined attack campaigns."""

        # APT29 Simulation
        apt29 = AttackCampaign(
            name="APT29 Simulation",
            description="Simulates APT29 (Cozy Bear) TTPs",
            threat_actor="APT29",
            techniques=[
                "T1059.001",  # PowerShell
                "T1087.001",  # Account Discovery
                "T1053.005",  # Scheduled Task
            ],
            success_criteria={
                'min_techniques_executed': 2,
                'required_techniques': ["T1059.001"]
            }
        )
        self.campaigns["apt29"] = apt29

        # Ransomware Simulation
        ransomware = AttackCampaign(
            name="Ransomware Simulation",
            description="Simulates common ransomware TTPs",
            threat_actor="Generic Ransomware",
            techniques=[
                "T1087.001",  # Discovery
                "T1059.001",  # Execution
                "T1053.005",  # Persistence
            ],
            success_criteria={
                'min_techniques_executed': 3
            }
        )
        self.campaigns["ransomware"] = ransomware

    def execute_campaign(self, campaign_name: str,
                        delay_seconds: int = 5) -> dict:
        """Execute a full attack campaign."""
        import time

        if campaign_name not in self.campaigns:
            return {'error': f"Unknown campaign: {campaign_name}"}

        campaign = self.campaigns[campaign_name]

        results = {
            'campaign': campaign.name,
            'threat_actor': campaign.threat_actor,
            'start_time': datetime.now().isoformat(),
            'technique_results': [],
            'success': False
        }

        print(f"\n{'='*60}")
        print(f"Starting Campaign: {campaign.name}")
        print(f"Threat Actor: {campaign.threat_actor}")
        print(f"{'='*60}\n")

        for i, technique_id in enumerate(campaign.techniques):
            print(f"[{i+1}/{len(campaign.techniques)}] Executing: {technique_id}")

            result = self.simulator.execute_technique(technique_id)
            results['technique_results'].append({
                'technique_id': technique_id,
                'success': result.success,
                'execution_time': result.execution_time,
                'error': result.error
            })

            if result.success:
                print(f"  ✓ Success ({result.execution_time:.2f}s)")
            else:
                print(f"  ✗ Failed: {result.error}")

            # Delay between techniques
            if i < len(campaign.techniques) - 1:
                time.sleep(delay_seconds)

        results['end_time'] = datetime.now().isoformat()

        # Evaluate success criteria
        successful = sum(1 for r in results['technique_results'] if r['success'])
        results['techniques_successful'] = successful

        if 'min_techniques_executed' in campaign.success_criteria:
            results['success'] = successful >= campaign.success_criteria['min_techniques_executed']

        return results

# Run campaign
campaign_sim = CampaignSimulator(simulator)
campaign_results = campaign_sim.execute_campaign("apt29", delay_seconds=2)
print(f"\nCampaign Success: {campaign_results['success']}")
```

---

## Task 4: Gap Analysis

### Identifying Detection Gaps

```python
class GapAnalyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def analyze_coverage(self, campaign_results: dict,
                        detection_results: list[dict]) -> dict:
        """Analyze detection coverage for a campaign."""

        # Match simulations to detections
        coverage = {
            'total_techniques': len(campaign_results['technique_results']),
            'detected': 0,
            'missed': 0,
            'detection_rate': 0.0,
            'gaps': []
        }

        for tech_result in campaign_results['technique_results']:
            technique_id = tech_result['technique_id']

            # Check if detected
            detected = any(
                d['technique_id'] == technique_id and d['detected']
                for d in detection_results
            )

            if detected:
                coverage['detected'] += 1
            else:
                coverage['missed'] += 1
                coverage['gaps'].append(technique_id)

        coverage['detection_rate'] = coverage['detected'] / coverage['total_techniques']

        return coverage

    def generate_gap_report(self, coverage: dict,
                           techniques: dict[str, MitreAttackTechnique]) -> str:
        """Generate comprehensive gap analysis report."""

        gaps_detail = []
        for technique_id in coverage['gaps']:
            if technique_id in techniques:
                tech = techniques[technique_id]
                gaps_detail.append({
                    'id': technique_id,
                    'name': tech.name,
                    'tactic': tech.tactic.value,
                    'detection_sources': tech.detection_sources
                })

        prompt = f"""Generate a detection gap analysis report:

## Coverage Summary
- Total Techniques Tested: {coverage['total_techniques']}
- Detected: {coverage['detected']}
- Missed: {coverage['missed']}
- Detection Rate: {coverage['detection_rate']*100:.1f}%

## Detection Gaps
{json.dumps(gaps_detail, indent=2)}

Generate a report with:
1. Executive Summary
2. Critical Gaps (prioritized by risk)
3. Recommended Mitigations for each gap
4. Implementation Roadmap (short/medium/long term)
5. Resource Requirements

Format as markdown."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def recommend_detections(self, gap_techniques: list[str],
                            techniques: dict[str, MitreAttackTechnique]) -> list[dict]:
        """Recommend specific detections for gap techniques."""

        recommendations = []

        for technique_id in gap_techniques:
            if technique_id not in techniques:
                continue

            tech = techniques[technique_id]

            prompt = f"""Provide specific detection recommendations for:

Technique: {tech.technique_id} - {tech.name}
Tactic: {tech.tactic.value}
Description: {tech.description}

Provide JSON with:
1. "sigma_rule": A Sigma detection rule
2. "splunk_query": Splunk SPL query
3. "elastic_query": Elastic EQL query
4. "log_requirements": Required log sources
5. "tuning_tips": Tips to reduce false positives"""

            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            try:
                rec = json.loads(response.content[0].text)
            except json.JSONDecodeError:
                rec = {'raw': response.content[0].text}

            rec['technique_id'] = technique_id
            recommendations.append(rec)

        return recommendations

# Analyze gaps
gap_analyzer = GapAnalyzer()

# Simulated detection results (in production, from SIEM validation)
detection_results = [
    {'technique_id': 'T1059.001', 'detected': True},
    {'technique_id': 'T1087.001', 'detected': False},
    {'technique_id': 'T1053.005', 'detected': True},
]

coverage = gap_analyzer.analyze_coverage(campaign_results, detection_results)
print(f"Detection Rate: {coverage['detection_rate']*100:.1f}%")
print(f"Gaps: {coverage['gaps']}")

# Generate report
report = gap_analyzer.generate_gap_report(coverage, simulator.techniques)
print(report)
```

---

## Task 5: Continuous Validation

### Automated Purple Team Testing

```python
import schedule
import time
from typing import Optional

class ContinuousPurpleTeam:
    def __init__(self, simulator: AttackSimulator,
                 validator: DetectionValidator,
                 notification_callback: Optional[Callable] = None):
        self.simulator = simulator
        self.validator = validator
        self.notify = notification_callback
        self.test_history = []

    def run_daily_test(self, techniques: list[str]):
        """Run daily detection validation tests."""

        results = {
            'timestamp': datetime.now().isoformat(),
            'techniques_tested': [],
            'detection_rate': 0.0
        }

        detected_count = 0

        for technique_id in techniques:
            # Execute simulation
            sim_time = datetime.now()
            sim_result = self.simulator.execute_technique(technique_id)

            # Wait for detection
            time.sleep(30)

            # Validate detection
            validation = self.validator.validate_detection(
                technique_id, sim_time, time_window_minutes=5
            )

            results['techniques_tested'].append({
                'technique_id': technique_id,
                'simulated': sim_result.success,
                'detected': validation['detected']
            })

            if validation['detected']:
                detected_count += 1

        results['detection_rate'] = detected_count / len(techniques) if techniques else 0

        self.test_history.append(results)

        # Alert on degradation
        if results['detection_rate'] < 0.8:
            self._alert_degradation(results)

        return results

    def _alert_degradation(self, results: dict):
        """Alert on detection capability degradation."""
        message = f"""
        ALERT: Detection Capability Degradation

        Detection Rate: {results['detection_rate']*100:.1f}%
        Time: {results['timestamp']}

        Missed Techniques:
        {[t['technique_id'] for t in results['techniques_tested'] if not t['detected']]}
        """

        if self.notify:
            self.notify(message)
        else:
            print(message)

    def get_trend_report(self, days: int = 30) -> dict:
        """Generate trend report for detection capabilities."""

        recent = self.test_history[-days:] if len(self.test_history) >= days else self.test_history

        if not recent:
            return {'error': 'No test history available'}

        rates = [r['detection_rate'] for r in recent]

        return {
            'period_days': len(recent),
            'average_detection_rate': sum(rates) / len(rates),
            'min_detection_rate': min(rates),
            'max_detection_rate': max(rates),
            'trend': 'improving' if rates[-1] > rates[0] else 'degrading' if rates[-1] < rates[0] else 'stable'
        }

# Setup continuous testing
continuous_pt = ContinuousPurpleTeam(simulator, validator)

# Schedule daily tests (example)
# schedule.every().day.at("03:00").do(
#     continuous_pt.run_daily_test,
#     techniques=["T1059.001", "T1087.001", "T1053.005"]
# )
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Simulations blocked by EDR | Whitelist test machines/processes |
| Detection timing issues | Increase validation time window |
| False validation failures | Check SIEM query syntax, log sources |
| Resource exhaustion | Rate limit simulations |
| Cleanup failures | Add manual cleanup procedures |

---

## Next Steps

- Add more technique simulations from ATT&CK
- Integrate with MITRE ATT&CK Navigator
- Build dashboard for coverage visualization
- Add threat intelligence integration
- Create automated remediation workflows
