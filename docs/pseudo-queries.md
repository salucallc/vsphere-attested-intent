# Pseudo-queries (not SIGMA), untested in a lab

Saluca Labs, 2026-11-19. Apache-2.0.

These are the stateful checks behind the attested-intent method. They need a join or a sequence, which SIGMA cannot express per event. Field and table names are placeholders. None has been run.

**1. Change attestation (the unmatched change is the alert).**
```
events  = mgmt_plane_changes(last 15m)          -- VAMI SSH PUT, SSO admin create, Global Permission grant,
                                                 -- ESXi authorized_keys write, syslog config change
records = approved_changes(window = event.time -/+ 60m, target = event.host, actor = event.actor)
ALERT   when no row in records matches (target, action_class, actor_or_group)
SEVERITY raise when event.actor is an SSO identity created within the last 24h
```
Needs an ITSM feed with a structured target and action class. If the change feed is unreachable the answer is ALERT, not silence (cannot tell is not a pass).

**2. VAMI SSH enable then disable inside one hour (GTIG step 8).**
```
sequence by appliance within 1h:
  [PUT /rest/appliance/access/ssh  (enable)]
  [PUT /rest/appliance/access/ssh  (disable)]
ALERT when both occur and no approved change covers the window
```
The enable and disable payload distinction: verify whether the access log carries the body.

**3. Hypervisor management exposure: TCP 2012 allowlist.**
```
conn where dst_port == 2012 and dst_host in vcsa_inventory and src_ip not in vcenter_peer_allowlist
```
GTIG exploits 123890 over TCP 2012 (S9). Peers legitimately on 2012 (Enhanced Linked Mode partners) must be inventoried first, verify which peers. Egress from VCSA to Slack API domains is the same shape: VCSA has no business there (LAZYBONES C2 is Slack, S9).

**4. Golden SAML correlation (hardest, weakest evidence).**
```
STS token issued for user U at time T
ALERT when no matching successful authentication event for U in the SSO log within 5m before T
```
Whether the SSO logs expose both sides with a joinable token or session id: verify. Prior art for the AD FS version of this correlation exists; for vCenter we could not find a published equivalent (2026-11-19 searches).

**5. Datastore dot-directories (file integrity).**
```
list /vmfs/volumes/*/ entries starting with '.' not in baseline  -> ALERT
```
Hidden `.a` staging is GTIG step 9. A scheduled directory listing from a trusted collector is the cheapest control that does not depend on shell.log surviving.
