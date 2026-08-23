# Playbook: Lateral Movement (T1021, T1046)

## Objective
Map the scope of an intruder moving between internal systems and identify the origin.

## Indicators
- Network scan patterns from one internal host to many others (T1046)
- Remote management protocol connections (RDP 3389 / SMB 445) from a host that rarely initiates them
- Same account authenticating across multiple hosts in rapid succession
- New service creation or scheduled tasks on remote hosts

## Investigation steps
1. Build the connection fan-out for the source host in the alert window.
2. List all successful remote logins by the suspect account; order by time.
3. Identify the patient-zero host and how the account was compromised there.
4. For each touched host, review process executions immediately following the login.
5. Check whether privileged accounts or domain infrastructure were targeted.

## Escalation criteria
- Movement toward servers or domain controllers
- Use of stolen service accounts
- Persistence mechanisms discovered on secondary hosts

## Containment
- Isolate affected hosts
- Reset credentials for the abused account and any accounts used remotely
- Block lateral protocols between network segments where unnecessary
