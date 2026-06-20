# Workflow Model

> **Target specification.** The current CLI reads a flat YAML request containing `id`, `name`, `method`, `url`, headers, and an optional body. It does not yet compile or run the multi-flow schema below. The example is a steering contract, not a claim of current support.

Workflows are file-native and Git-friendly. Use a strict versioned schema in YAML or TOML with generated JSON Schema for validation and editor completion. The UI edits the same files the CLI validates and runs.

## Proposed Shape

```yaml
version: 1
name: api-and-dns-capacity

profiles:
  local:
    vars:
      api_base: "https://api.example.test"
      resolver: "1.1.1.1:853"

secrets:
  api_token:
    source: keychain
    key: example-api-token

variables:
  tenant:
    list: ["alpha", "beta", "gamma"]
  request_id:
    generator: uuid_v7

flows:
  fetch-user:
    kind: http
    stages:
      - http:
          method: GET
          url: "{{vars.api_base}}/v1/users/{{vars.tenant}}"
          headers:
            authorization: "Bearer {{secrets.api_token}}"
            x-request-id: "{{vars.request_id}}"
      - assert:
          status: 200
          latency_p95_ms_lt: 250

  dot-query:
    kind: dns
    stages:
      - tcp_connect:
          target: "{{vars.resolver}}"
      - tls:
          sni: "cloudflare-dns.com"
          alpn: ["dot"]
      - dns:
          qname: "{{vars.tenant}}.example.com"
          qtype: A
          edns0:
            udp_size: 1232
            options:
              - code: 65184
                payload_hex: "cafe"

experiments:
  find-maximum-load:
    type: auto_ladder
    flows: ["fetch-user", "dot-query"]
    climb:
      mode: qps_then_workers
      qps_start: 100
      qps_step: 100
      interval: 30s
      max_workers: 16
    stop_when:
      error_rate_gt: 0.01
      timeout_rate_gt: 0.005
      latency_p99_ms_gt: 750
    cool_down: 20s
```

## Compilation Boundary

Before execution, the compiler:

1. Parses with an established serialization library and rejects unknown or invalid fields.
2. Resolves the profile and validates all variable and secret references.
3. Checks protocol-stage compatibility and connection policy.
4. Resolves target safety policy without exposing secret values.
5. Indexes corpora and creates immutable run inputs.
6. Produces a deterministic plan with a workflow hash and random seed.

No YAML parsing, template expansion, schema lookup, or keychain access belongs on the traffic hot path.

## Versioning Rules

- `version` is required and changes only for incompatible schema changes.
- Unknown fields are errors by default so misspellings do not silently alter traffic.
- Stable formatting keeps diffs reviewable.
- Generated JSON Schema is derived from the same Rust domain types used by the compiler.
- Report snapshots record the schema version, workflow hash, resolved non-secret configuration, and Git state.
