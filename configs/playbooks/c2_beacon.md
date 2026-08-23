# Playbook: Command and Control Beaconing (T1071, T1573)

## Objective
Identify compromised hosts by detecting periodic low-volume traffic to external infrastructure.

## Indicators
- Regular-interval outbound connections (consistent timing with small jitter)
- Small, nearly identical payload sizes per connection
- Destination IP/domain with no organizational history or short registration age
- Traffic on non-standard ports or rare user agents over HTTPS

## Investigation steps
1. Compute inter-connection interval statistics for the host/destination pair; beaconing shows low standard deviation.
2. Check destination reputation in threat intelligence feeds.
3. Identify the process making the connections (EDR network events).
4. Review what executed on the host before the beacons began.
5. Search for other hosts contacting the same infrastructure.

## Escalation criteria
- Known-malicious destination
- Process is unsigned/unusual or running from temp directories
- Multiple hosts beaconing to the same destination

## Containment
- Block the destination and related indicators
- Isolate and reimage the host if compromise is confirmed
- Hunt retroactively for the same indicators across the estate
