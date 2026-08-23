# Playbook: Ransomware Encryption Activity (T1486, T1059)

## Objective
Confirm or rule out active ransomware encryption on a host and identify patient-zero entry point.

## Indicators
- Script interpreter (powershell/cmd/wsh) spawning unusual child processes
- Mass file modification or rename events (often adding extensions like .locked, .encrypted) on a single host
- Credential dumping tool indicators shortly before encryption
- New outbound connection to external infrastructure after file modifications
- Shadow copy deletion commands

## Investigation steps
1. Collect the full process tree for the suspicious process execution on the affected host.
2. Count distinct files modified per minute; ransomware typically exceeds 50/minute.
3. Identify the initial access vector: review authentication events, email attachments, and downloads in the preceding 48 hours.
4. Extract the external destination IPs contacted after encryption began; check them against threat intelligence.
5. Determine lateral spread: check whether other hosts show the same process or file patterns.

## Escalation criteria
- Confirmed mass encryption with external C2 contact
- Multiple hosts affected
- Backup infrastructure targeted

## Containment
- Isolate the affected host at the network layer immediately
- Block identified C2 destinations
- Suspend the compromised user account
- Preserve forensic images before remediation
