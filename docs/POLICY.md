# Security policy

`policy/policy.json` is the default configuration. Each client may load a different file with `--policy`. The client loads it when the process starts, and binds its policy and measured profile into negotiation signatures.

```json
{
  "minimum_security_level": 3,
  "allow_experimental": false,
  "performance_preference": "latency",
  "algorithms": {
    "ML-KEM-768": {"status": "recommended", "priority": 1},
    "HQC-3": {"status": "experimental", "priority": 2}
  }
}
```

`minimum_security_level` accepts integers 1 through 5. Both implemented KEMs claim level 3, so a minimum above 3 leaves no acceptable candidate. `status` accepts `recommended`, `experimental`, or `prohibited`. Priorities are nonnegative integers up to 1000; lower values are preferred. Preferences are `latency`, `cpu`, `memory`, `bandwidth`, and `balanced`.

The selection engine intersects the two offered capability lists and verifies its own installed implementations. It rejects a candidate if either policy prohibits it, lacks its rule, requires a higher level, or disallows an experimental implementation. Reclassifying HQC-3 as recommended in a JSON file does not remove its implementation's experimental status.

Among remaining candidates, it orders by recommended versus experimental status, sum of the two priorities, normalized measured performance score, and algorithm identifier as a deterministic tie-break. Measurements influence selection only when the required metric is finite, nonnegative, and comparable across all candidates in both signed snapshots. Missing measurements produce an explicit deterministic fallback. Neither signed measurements nor signatures establish that a malicious peer reported honest performance, so security admissibility always comes first.

## Laboratory examples

To require HQC-3 in an experiment, make a copy of the policy for each client. Set `allow_experimental` to `true` in both copies and prohibit ML-KEM-768:

```json
{
  "minimum_security_level": 3,
  "allow_experimental": true,
  "performance_preference": "latency",
  "algorithms": {
    "ML-KEM-768": {"status": "prohibited", "priority": 1},
    "HQC-3": {"status": "experimental", "priority": 2}
  }
}
```

Start both clients with their respective `--policy` file. This creates a new HQC session; it does not change an established ML-KEM session in place. The default policy continues to prefer ML-KEM-768 even if HQC timing happens to be lower on a machine, because experimental status outranks speed.

To demonstrate refusal, prohibit ML-KEM-768 while leaving `allow_experimental` false, or require minimum level 4. The clients should reject establishment with a policy reason. Do not edit application code to make a prohibited session succeed.

The engine selects among known implementations and configured rules. It does not discover unknown vulnerabilities or infer cryptographic safety from benchmark speed.
