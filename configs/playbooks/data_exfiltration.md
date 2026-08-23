# Playbook: Data Exfiltration (T1048, T1005)

## Objective
Determine whether bulk sensitive-file access followed by abnormal outbound transfer constitutes data theft.

## Indicators
- Unusual volume of file reads from sensitive shares by one account
- Outbound transfer volume far above the host's historical baseline
- Transfer to rarely-used or external destinations, unusual ports (8443, 587, custom)
- Access outside the user's normal working pattern

## Investigation steps
1. Sum outbound bytes per destination for the suspect host over 24h; compare with a 30-day baseline.
2. List files accessed by the user in the hours before the transfer; flag sensitive paths.
3. Check whether the destination domain/IP has prior history in proxy logs.
4. Verify whether the transferred content correlates with accessed documents by volume.
5. Check for staging behavior: archives created (zip/7z/rar) before upload.

## Escalation criteria
- Sensitive share access immediately preceding large external transfer
- Destination is newly observed infrastructure
- User account recently had credential anomalies

## Containment
- Quarantine the host
- Block the destination at firewall/proxy level
- Initiate insider-threat or compromised-credential response track
