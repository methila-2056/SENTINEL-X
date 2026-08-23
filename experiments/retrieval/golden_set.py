"""Golden retrieval evaluation set.

Each query maps to a set of relevant MITRE technique external_ids that exist
in the ingested knowledge base. Relevance is defined by the technique the
query describes, not by string matching.
"""

GOLDEN_QUERIES: dict[str, set[str]] = {
    "adversary dumping lsass memory to steal credentials": {"T1003"},
    "powershell encoded command execution for script abuse": {"T1059.001", "T1059"},
    "mass file encryption with new extensions by ransomware": {"T1486"},
    "periodic beaconing to command and control server over https": {"T1071.001", "T1071"},
    "password spraying many failed logins against one account": {"T1110.003", "T1110"},
    "ssh brute force authentication attempts": {"T1110.001", "T1110"},
    "remote desktop protocol movement between internal hosts": {"T1021.001", "T1021"},
    "smb admin shares used to move laterally": {"T1021.002", "T1021"},
    "internal network scanning to discover other systems": {"T1046"},
    "large outbound upload of collected documents to external server": {"T1048", "T1567"},
    "deleting shadow copies to prevent recovery": {"T1490"},
    "scheduled task persistence on windows host": {"T1053.005", "T1053"},
    "registry run key startup persistence": {"T1547.001", "T1547"},
    "web shell access on internet facing server": {"T1505.003", "T1505"},
    "email phishing attachment initial access": {"T1566.001", "T1566"},
    "exploitation of public facing application vulnerability": {"T1190"},
    "creating local administrator account for persistence": {"T1136.001", "T1136"},
    "clearing event logs to cover tracks": {"T1070.001", "T1070"},
    "data staged in archive before exfiltration": {"T1074", "T1560"},
    "pass the hash using stolen ntlm hashes": {"T1550.002", "T1550"},
    "dns tunneling for covert channel communication": {"T1071.004"},
    "kerberoasting service ticket requests for cracking": {"T1558.003", "T1558"},
    "disable security tools to evade defenses": {"T1562.001", "T1562"},
    "process injection into legitimate system binary": {"T1055"},
    "os credential files password stores in etc passwd": {"T1003.008", "T1555"},
}
