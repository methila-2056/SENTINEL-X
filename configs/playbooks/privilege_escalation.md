# Playbook: Privilege Escalation (T1548, T1068)

## Objective
Verify whether a privilege change is authorized and detect abuse of elevated rights.

## Indicators
- Account added to privileged group outside change-management windows
- Elevation followed immediately by access to sensitive data
- Exploit-like process behavior preceding elevation (T1068)
- Service account performing interactive logins

## Investigation steps
1. Confirm the privilege change event source and whether a matching change ticket exists.
2. Review all activity by the account between elevation and now, especially sensitive file access.
3. Check for exploit indicators: crash dumps, unusual service installs, kernel driver loads.
4. Determine what the account accessed historically to establish baseline deviation.

## Escalation criteria
- No change record for the elevation
- Sensitive data access after unauthorized elevation
- Targeting of domain admin groups

## Containment
- Revert the unauthorized group membership
- Reset the account password and revoke sessions
- Investigate how elevation was achieved before restoring access
