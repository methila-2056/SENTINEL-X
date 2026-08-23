# Playbook: Brute Force / Password Spraying (T1110)

## Objective
Determine whether a burst of failed authentications followed by a successful login represents a credential attack against the target account.

## Indicators
- >= 10 failed logins for one account within 15 minutes
- Failures originate from a single external source IP or small set of IPs
- Successful login from the same source IP within 30 minutes of failures
- Login outside normal working hours for the account

## Investigation steps
1. Pull all authentication events for the target user in a +/-24h window around the burst.
2. Group failed logins by source IP; check whether the success event shares that source IP.
3. Check whether the source IP is present in threat intelligence (known scanner, TOR exit, bulletproof host).
4. Review what the account did immediately after the successful login: process executions, network connections, file access.
5. Compare post-login activity to the account's historical baseline (usual workstation, usual hours, usual applications).

## Escalation criteria
- Success from the same external IP as the failure burst
- Post-login activity includes rare processes, mass file reads, or new outbound connections
- Account has privileged group membership

## Containment
- Disable or force password reset for the targeted account
- Block the offending source IP at the perimeter
- Invalidate active sessions for the account
