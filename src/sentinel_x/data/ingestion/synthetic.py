"""Synthetic enterprise telemetry generator with ground-truth attack scenarios.

Generates realistic benign activity (working-hours logins, app usage, internal
traffic) and injects MITRE-mapped attack chains. Every event carries ground
truth labels (`label`, `attack_category`, `technique_id`, `incident_id`) so the
detection, correlation, retrieval and agent layers can all be evaluated.
"""

import json
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import structlog

from sentinel_x.data.schemas.event import Action, EventType, Label

logger = structlog.get_logger(__name__)

# --- Enterprise world definition ---------------------------------------------

FIRST_NAMES = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "kevin",
    "linda",
    "mallory",
    "niajal",
    "olivia",
    "peggy",
    "quinn",
    "rupert",
    "sybil",
    "trent",
    "uma",
    "victor",
    "wendy",
    "xavier",
]
DEPARTMENTS = ["finance", "engineering", "hr", "sales", "it_admin"]

INTERNAL_SUBNET = "10.0.{third}.{host}"
EXTERNAL_IPS = ["203.0.113.{n}", "198.51.100.{n}"]
KNOWN_BAD_IPS = ["185.220.101.{n}", "45.155.205.{n}", "91.219.236.{n}"]

BENIGN_PROCESSES = ["chrome.exe", "outlook.exe", "excel.exe", "teams.exe", "code.exe"]
ADMIN_PROCESSES = ["cmd.exe", "server_manager.exe", "backup_agent.exe"]
SUSPICIOUS_PROCESSES = {
    "ransomware": "encryptor.ps1",
    "recon": "net_scan.exe",
    "credential_dump": "mimikatz.exe",
}
SENSITIVE_PATHS = [
    r"\\fileserver\finance\payroll_2026.xlsx",
    r"\\fileserver\hr\employee_records.mdb",
    r"\\fileserver\engineering\source_archive.zip",
]

# --- Scenario templates -------------------------------------------------------
# Each returns list of event dicts appended to the stream.


class ScenarioContext:
    def __init__(self, rng: np.random.Generator):
        self.rng = rng

    def bad_ip(self) -> str:
        template = KNOWN_BAD_IPS[self.rng.integers(len(KNOWN_BAD_IPS))]
        return template.format(n=int(self.rng.integers(1, 250)))

    def internal_ip(self) -> str:
        return INTERNAL_SUBNET.format(
            third=int(self.rng.integers(1, 5)), host=int(self.rng.integers(10, 200))
        )


def _ev(**kwargs) -> dict:
    base = {
        "user": None,
        "host": None,
        "process": None,
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "file_path": None,
        "bytes_transferred": None,
        "severity": 1,
        "label": Label.BENIGN.value,
        "attack_category": None,
        "technique_id": None,
        "incident_id": None,
        "metadata": {},
    }
    base.update(kwargs)
    return base


def _host_to_ip(host: str) -> str:
    """Deterministic internal IP derived from the hostname (stable across processes)."""
    h = zlib.crc32(host.encode())
    return f"10.0.{h % 4 + 1}.{h % 190 + 10}"


class AttackScenarios:
    """Attack chain templates. Each yields (events, ground_truth_incident)."""

    def __init__(self, ctx: ScenarioContext):
        self.ctx = ctx

    def brute_force(
        self, incident_id: str, start: datetime, target_user: str, target_host: str
    ) -> tuple[list[dict], dict]:
        ip = self.ctx.bad_ip()
        events = []
        n_failures = int(self.ctx.rng.integers(25, 60))
        t = start
        for _i in range(n_failures):
            events.append(
                _ev(
                    timestamp=t,
                    source="auth_log",
                    event_type=EventType.AUTHENTICATION.value,
                    action=Action.LOGIN_FAILURE.value,
                    user=target_user,
                    host=target_host,
                    src_ip=ip,
                    dst_port=3389,
                    severity=3,
                    label=Label.ATTACK.value,
                    attack_category="brute_force",
                    technique_id="T1110",
                    incident_id=incident_id,
                )
            )
            t += timedelta(seconds=float(self.ctx.rng.integers(2, 15)))
        success_t = t + timedelta(seconds=float(self.ctx.rng.integers(5, 30)))
        events.append(
            _ev(
                timestamp=success_t,
                source="auth_log",
                event_type=EventType.AUTHENTICATION.value,
                action=Action.LOGIN_SUCCESS.value,
                user=target_user,
                host=target_host,
                src_ip=ip,
                dst_port=3389,
                severity=8,
                label=Label.ATTACK.value,
                attack_category="brute_force",
                technique_id="T1110",
                incident_id=incident_id,
            )
        )
        gt_start = start
        gt_end = success_t
        return events, dict(
            scenario="brute_force",
            technique_ids=["T1110"],
            start_time=gt_start,
            end_time=gt_end,
            compromised_users=[target_user],
            compromised_hosts=[target_host],
            description=f"Password spraying against {target_user} from {ip}, followed by successful login",
        )

    def ransomware(
        self, incident_id: str, start: datetime, user: str, host: str
    ) -> tuple[list[dict], dict]:
        ip = self.ctx.internal_ip()
        proc = SUSPICIOUS_PROCESSES["ransomware"]
        events = [
            _ev(
                timestamp=start,
                source="edr",
                event_type=EventType.PROCESS_EXECUTION.value,
                action=Action.EXECUTE.value,
                user=user,
                host=host,
                process=proc,
                severity=7,
                label=Label.ATTACK.value,
                attack_category="ransomware",
                technique_id="T1059",
                incident_id=incident_id,
            ),
            _ev(
                timestamp=start + timedelta(seconds=20),
                source="edr",
                event_type=EventType.PROCESS_EXECUTION.value,
                action=Action.EXECUTE.value,
                user=user,
                host=host,
                process=SUSPICIOUS_PROCESSES["credential_dump"],
                severity=9,
                label=Label.ATTACK.value,
                attack_category="ransomware",
                technique_id="T1003",
                incident_id=incident_id,
            ),
        ]
        t = start + timedelta(seconds=60)
        n_files = int(self.ctx.rng.integers(80, 150))
        for _ in range(n_files):
            path = SENSITIVE_PATHS[int(self.ctx.rng.integers(len(SENSITIVE_PATHS)))]
            events.append(
                _ev(
                    timestamp=t,
                    source="edr",
                    event_type=EventType.FILE_ACCESS.value,
                    action=Action.FILE_MODIFY.value,
                    user=user,
                    host=host,
                    process=proc,
                    file_path=path + ".locked",
                    bytes_transferred=int(self.ctx.rng.integers(1024, 10**7)),
                    severity=6,
                    label=Label.ATTACK.value,
                    attack_category="ransomware",
                    technique_id="T1486",
                    incident_id=incident_id,
                )
            )
            t += timedelta(seconds=float(self.ctx.rng.integers(1, 8)))
        beacon_ip = self.ctx.bad_ip()
        events.append(
            _ev(
                timestamp=t + timedelta(seconds=30),
                source="firewall",
                event_type=EventType.NETWORK_CONNECTION.value,
                action=Action.CONNECT.value,
                host=host,
                src_ip=ip,
                dst_ip=beacon_ip,
                dst_port=443,
                bytes_transferred=int(self.ctx.rng.integers(10**6, 10**8)),
                severity=9,
                label=Label.ATTACK.value,
                attack_category="ransomware",
                technique_id="T1071",
                incident_id=incident_id,
            )
        )
        return events, dict(
            scenario="ransomware_encryption",
            technique_ids=["T1059", "T1003", "T1486", "T1071"],
            start_time=start,
            end_time=t + timedelta(seconds=30),
            compromised_users=[user],
            compromised_hosts=[host],
            description="Suspicious script execution followed by mass file encryption and external contact",
        )

    def data_exfiltration(
        self, incident_id: str, start: datetime, user: str, host: str
    ) -> tuple[list[dict], dict]:
        ip = self.ctx.internal_ip()
        events = []
        t = start
        for _ in range(int(self.ctx.rng.integers(15, 40))):
            path = SENSITIVE_PATHS[int(self.ctx.rng.integers(len(SENSITIVE_PATHS)))]
            events.append(
                _ev(
                    timestamp=t,
                    source="edr",
                    event_type=EventType.FILE_ACCESS.value,
                    action=Action.FILE_READ.value,
                    user=user,
                    host=host,
                    process=self.ctx.rng.choice(BENIGN_PROCESSES),
                    file_path=path,
                    bytes_transferred=int(self.ctx.rng.integers(10**5, 10**7)),
                    severity=4,
                    label=Label.ATTACK.value,
                    attack_category="exfiltration",
                    technique_id="T1005",
                    incident_id=incident_id,
                )
            )
            t += timedelta(seconds=float(self.ctx.rng.integers(5, 60)))
        ext_ip = EXTERNAL_IPS[int(self.ctx.rng.integers(len(EXTERNAL_IPS)))].format(
            n=int(self.ctx.rng.integers(1, 250))
        )
        upload_end = t + timedelta(minutes=float(self.ctx.rng.integers(5, 40)))
        events.append(
            _ev(
                timestamp=upload_end,
                source="firewall",
                event_type=EventType.NETWORK_CONNECTION.value,
                action=Action.CONNECT.value,
                host=host,
                src_ip=ip,
                dst_ip=ext_ip,
                dst_port=8443,
                bytes_transferred=int(self.ctx.rng.integers(5 * 10**8, 2 * 10**9)),
                severity=9,
                label=Label.ATTACK.value,
                attack_category="exfiltration",
                technique_id="T1048",
                incident_id=incident_id,
            )
        )
        return events, dict(
            scenario="data_exfiltration",
            technique_ids=["T1005", "T1048"],
            start_time=start,
            end_time=upload_end,
            compromised_users=[user],
            compromised_hosts=[host],
            description=f"Bulk sensitive-file reads from {user} followed by large outbound transfer to {ext_ip}",
        )

    def lateral_movement(
        self, incident_id: str, start: datetime, user: str, origin_host: str, targets: list[str]
    ) -> tuple[list[dict], dict]:
        ip = self.ctx.internal_ip()
        events = []
        t = start
        scan_proc = SUSPICIOUS_PROCESSES["recon"]
        events.append(
            _ev(
                timestamp=t,
                source="edr",
                event_type=EventType.PROCESS_EXECUTION.value,
                action=Action.EXECUTE.value,
                user=user,
                host=origin_host,
                process=scan_proc,
                severity=7,
                label=Label.ATTACK.value,
                attack_category="lateral_movement",
                technique_id="T1046",
                incident_id=incident_id,
            )
        )
        t += timedelta(minutes=float(self.ctx.rng.integers(2, 10)))
        touched_hosts = [origin_host]
        for target in targets:
            port = int(self.ctx.rng.choice([3389, 445]))
            events.append(
                _ev(
                    timestamp=t,
                    source="firewall",
                    event_type=EventType.NETWORK_CONNECTION.value,
                    action=Action.CONNECT.value,
                    host=origin_host,
                    src_ip=ip,
                    dst_ip=_host_to_ip(target),
                    dst_port=port,
                    severity=6,
                    label=Label.ATTACK.value,
                    attack_category="lateral_movement",
                    technique_id="T1021",
                    incident_id=incident_id,
                    metadata={"target_host": target},
                )
            )
            events.append(
                _ev(
                    timestamp=t + timedelta(seconds=30),
                    source="auth_log",
                    event_type=EventType.AUTHENTICATION.value,
                    action=Action.LOGIN_SUCCESS.value,
                    user=user,
                    host=target,
                    src_ip=ip,
                    dst_port=port,
                    severity=7,
                    label=Label.ATTACK.value,
                    attack_category="lateral_movement",
                    technique_id="T1021",
                    incident_id=incident_id,
                )
            )
            touched_hosts.append(target)
            t += timedelta(minutes=float(self.ctx.rng.integers(5, 25)))
        return events, dict(
            scenario="lateral_movement",
            technique_ids=["T1046", "T1021"],
            start_time=start,
            end_time=t,
            compromised_users=[user],
            compromised_hosts=touched_hosts,
            description=f"Internal scan from {origin_host} followed by remote logins across {len(targets)} hosts",
        )

    def c2_beacon(
        self, incident_id: str, start: datetime, user: str, host: str
    ) -> tuple[list[dict], dict]:
        ip = self.ctx.internal_ip()
        beacon_ip = self.ctx.bad_ip()
        events = []
        t = start
        n_beacons = int(self.ctx.rng.integers(30, 70))
        interval = float(self.ctx.rng.integers(55, 65))
        for _ in range(n_beacons):
            events.append(
                _ev(
                    timestamp=t,
                    source="firewall",
                    event_type=EventType.NETWORK_CONNECTION.value,
                    action=Action.CONNECT.value,
                    host=host,
                    src_ip=ip,
                    dst_ip=beacon_ip,
                    dst_port=int(self.ctx.rng.choice([443, 8080])),
                    bytes_transferred=int(self.ctx.rng.integers(500, 4000)),
                    severity=5,
                    label=Label.ATTACK.value,
                    attack_category="c2",
                    technique_id="T1071",
                    incident_id=incident_id,
                )
            )
            t += timedelta(seconds=interval + float(self.ctx.rng.normal(0, 2)))
        return events, dict(
            scenario="c2_beacon",
            technique_ids=["T1071"],
            start_time=start,
            end_time=t,
            compromised_users=[user],
            compromised_hosts=[host],
            description=f"Periodic low-volume beacons from {host} to {beacon_ip}",
        )

    def privilege_escalation(
        self, incident_id: str, start: datetime, user: str, host: str
    ) -> tuple[list[dict], dict]:
        events = []
        events.append(
            _ev(
                timestamp=start,
                source="edr",
                event_type=EventType.PRIVILEGE_CHANGE.value,
                action=Action.PRIVILEGE_ESCALATE.value,
                user=user,
                host=host,
                severity=8,
                label=Label.ATTACK.value,
                attack_category="privilege_escalation",
                technique_id="T1548",
                incident_id=incident_id,
                metadata={"from_group": "users", "to_group": "administrators"},
            )
        )
        t = start + timedelta(minutes=float(self.ctx.rng.integers(1, 5)))
        path = SENSITIVE_PATHS[int(self.ctx.rng.integers(len(SENSITIVE_PATHS)))]
        events.append(
            _ev(
                timestamp=t,
                source="edr",
                event_type=EventType.FILE_ACCESS.value,
                action=Action.FILE_READ.value,
                user=user,
                host=host,
                process="cmd.exe",
                file_path=path,
                bytes_transferred=int(self.ctx.rng.integers(10**4, 10**6)),
                severity=7,
                label=Label.ATTACK.value,
                attack_category="privilege_escalation",
                technique_id="T1548",
                incident_id=incident_id,
            )
        )
        return events, dict(
            scenario="privilege_escalation",
            technique_ids=["T1548"],
            start_time=start,
            end_time=t,
            compromised_users=[user],
            compromised_hosts=[host],
            description=f"{user} elevated to administrators then accessed {path}",
        )


SCENARIO_REGISTRY = {
    "brute_force": "brute_force",
    "ransomware": "ransomware",
    "exfiltration": "data_exfiltration",
    "lateral_movement": "lateral_movement",
    "c2_beacon": "c2_beacon",
    "priv_esc": "privilege_escalation",
}


# --- Benign behavior ----------------------------------------------------------


def generate_benign_events(
    users: list[dict],
    hosts: list[str],
    days: int,
    rng: np.random.Generator,
    day_start: datetime,
) -> list[dict]:
    events: list[dict] = []
    for day_offset in range(days):
        base_day = day_start + timedelta(days=day_offset)
        weekend = base_day.weekday() >= 5
        active_users = [u for u in users if not (weekend and u["role"] != "it_admin")]
        if not active_users:
            continue
        for user in active_users:
            login_hour = float(rng.normal(9 if not weekend else 11, 0.75))
            login_hour = min(max(login_hour, 7.0), 18.0)
            login_dt = base_day.replace(hour=int(login_hour), minute=int((login_hour % 1) * 60))
            user_ip = f"10.0.{rng.integers(1, 5)}.{user['ip_last']}"
            # Occasional failed login (fat-fingered password)
            if rng.random() < 0.03:
                events.append(
                    _ev(
                        timestamp=login_dt - timedelta(minutes=float(rng.uniform(0.5, 5))),
                        source="auth_log",
                        event_type=EventType.AUTHENTICATION.value,
                        action=Action.LOGIN_FAILURE.value,
                        user=user["username"],
                        host=user["workstation"],
                        src_ip=user_ip,
                        dst_port=389,
                        severity=1,
                    )
                )
            events.append(
                _ev(
                    timestamp=login_dt,
                    source="auth_log",
                    event_type=EventType.AUTHENTICATION.value,
                    action=Action.LOGIN_SUCCESS.value,
                    user=user["username"],
                    host=user["workstation"],
                    src_ip=user_ip,
                    dst_port=389,
                    severity=0,
                )
            )
            # App launches through the day
            session_hours = float(rng.uniform(6, 10))
            n_apps = int(rng.integers(8, 30))
            for _ in range(n_apps):
                t = login_dt + timedelta(minutes=float(rng.uniform(1, session_hours * 60)))
                proc = BENIGN_PROCESSES[int(rng.integers(len(BENIGN_PROCESSES)))]
                events.append(
                    _ev(
                        timestamp=t,
                        source="edr",
                        event_type=EventType.PROCESS_EXECUTION.value,
                        action=Action.EXECUTE.value,
                        user=user["username"],
                        host=user["workstation"],
                        process=proc,
                        severity=0,
                    )
                )
            # Routine internal connections
            n_conns = int(rng.integers(10, 40))
            for _ in range(n_conns):
                t = login_dt + timedelta(minutes=float(rng.uniform(1, session_hours * 60)))
                events.append(
                    _ev(
                        timestamp=t,
                        source="flow_sensor",
                        event_type=EventType.NETWORK_CONNECTION.value,
                        action=Action.CONNECT.value,
                        host=user["workstation"],
                        src_ip=user_ip,
                        dst_ip=f"10.0.{rng.integers(1, 5)}.{rng.integers(10, 200)}",
                        dst_port=int(rng.choice([443, 80, 445, 1433])),
                        bytes_transferred=int(rng.integers(10**3, 10**7)),
                        severity=0,
                    )
                )
            # Occasional document edits on the file share
            n_files = int(rng.integers(0, 6))
            for _ in range(n_files):
                t = login_dt + timedelta(minutes=float(rng.uniform(30, session_hours * 60)))
                path = SENSITIVE_PATHS[int(rng.integers(len(SENSITIVE_PATHS)))]
                events.append(
                    _ev(
                        timestamp=t,
                        source="edr",
                        event_type=EventType.FILE_ACCESS.value,
                        action=rng.choice([Action.FILE_READ.value, Action.FILE_MODIFY.value]),
                        user=user["username"],
                        host=user["workstation"],
                        process=rng.choice(["excel.exe", "word.exe"]),
                        file_path=path,
                        bytes_transferred=int(rng.integers(10**3, 10**6)),
                        severity=0,
                    )
                )
    return events


def build_world(seed: int) -> tuple[list[dict], list[str]]:
    users = []
    for i, name in enumerate(FIRST_NAMES):
        dept = DEPARTMENTS[i % len(DEPARTMENTS)]
        role = "it_admin" if dept == "it_admin" else "employee"
        users.append(
            {
                "username": name,
                "department": dept,
                "role": role,
                "workstation": f"WS-{100 + i}",
                "ip_last": 10 + i * 3,
            }
        )
    servers = [f"SRV-{i:02d}" for i in range(1, 9)]
    hosts = [u["workstation"] for u in users] + servers
    return users, hosts


def generate_dataset(
    out_dir: Path,
    seed: int = 42,
    days: int = 7,
    n_attacks: int = 12,
    day_start: datetime | None = None,
) -> tuple[pd.DataFrame, list[dict]]:
    """Generate the full synthetic dataset. Returns (events_df, incidents)."""
    rng = np.random.default_rng(seed)
    ctx = ScenarioContext(rng)
    scenarios_api = AttackScenarios(ctx)
    if day_start is None:
        day_start = datetime.now(UTC).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=days)

    users, hosts = build_world(seed)

    # Place attacks at random times within the window
    total_seconds = days * 24 * 3600 - 7200
    attack_times = sorted(
        day_start + timedelta(seconds=float(rng.integers(3600 * 8, total_seconds)))
        for _ in range(n_attacks)
    )
    scenario_names = list(SCENARIO_REGISTRY.keys())
    chosen = [scenario_names[int(rng.integers(len(scenario_names)))] for _ in range(n_attacks)]

    attacks: list[tuple[str, list[dict], dict]] = []
    for idx, (scen_name, atk_start) in enumerate(zip(chosen, attack_times, strict=False)):
        incident_id = f"INC-{1000 + idx}"
        user = users[int(rng.integers(len(users)))]
        if scen_name == "brute_force":
            evs, gt = scenarios_api.brute_force(
                incident_id, atk_start, user["username"], user["workstation"]
            )
        elif scen_name == "ransomware":
            evs, gt = scenarios_api.ransomware(
                incident_id, atk_start, user["username"], user["workstation"]
            )
        elif scen_name == "exfiltration":
            evs, gt = scenarios_api.data_exfiltration(
                incident_id, atk_start, user["username"], user["workstation"]
            )
        elif scen_name == "lateral_movement":
            pool = [h for h in hosts if h != user["workstation"]]
            targets = [pool[int(rng.integers(len(pool)))] for _ in range(int(rng.integers(2, 4)))]
            evs, gt = scenarios_api.lateral_movement(
                incident_id, atk_start, user["username"], user["workstation"], targets
            )
        elif scen_name == "c2_beacon":
            evs, gt = scenarios_api.c2_beacon(
                incident_id, atk_start, user["username"], user["workstation"]
            )
        elif scen_name == "priv_esc":
            evs, gt = scenarios_api.privilege_escalation(
                incident_id, atk_start, user["username"], user["workstation"]
            )
        else:
            raise ValueError(f"Unknown scenario {scen_name}")
        attacks.append((incident_id, evs, gt))

    benign = generate_benign_events(users, hosts, days, rng, day_start)

    all_events = benign + [e for _, evs, _ in attacks for e in evs]
    df = pd.DataFrame(all_events)
    df.insert(0, "event_id", ["syn-" + str(i) for i in range(len(df))])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = ["syn-" + str(i) for i in range(len(df))]  # re-key after sort
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

    incidents = []
    for incident_id, _evs, gt in attacks:
        member = df[df["incident_id"] == incident_id]
        gt_full = {
            "incident_id": incident_id,
            **gt,
            "event_count": len(member),
            "first_event_id": str(member.iloc[0]["event_id"]) if len(member) else None,
        }
        incidents.append(gt_full)

    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / "events.parquet"
    df_out = df.copy()
    df_out["metadata"] = df_out["metadata"].apply(json.dumps)
    df_out.to_parquet(events_path, index=False)
    incidents_path = out_dir / "incidents_ground_truth.json"
    with open(incidents_path, "w") as fh:
        json.dump(incidents, fh, indent=2, default=str)
    logger.info(
        "synthetic_dataset_written",
        events=len(df),
        attacks=n_attacks,
        path=str(events_path),
    )
    report = (
        df.groupby(["label", "attack_category"], dropna=False).size().rename("rows").reset_index()
    )
    report.to_csv(out_dir / "label_report.csv", index=False)
    return df, incidents


def write_jsonl_sample(df: pd.DataFrame, path: Path, n: int = 25) -> None:
    sample = df.head(n).copy()
    sample["metadata"] = sample["metadata"].apply(json.dumps)
    sample.to_json(path, orient="records", lines=True)
