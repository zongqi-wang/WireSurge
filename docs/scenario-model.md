# Scenario Model

> **Target specification.** The current CLI reads a flat YAML request containing `id`, `name`, `method`, `url`, headers, and an optional body, plus the single-request `vars`/`expect` extension that `wiresurge run` already executes. It does not yet compile or run the multi-step scenario schema below. The example is a steering contract, not a claim of current support.

Scenarios are file-native and Git-friendly. Use a strict versioned schema in YAML or TOML with generated JSON Schema for validation and editor completion. The UI edits the same files the CLI validates and runs.

A scenario is an ordered list of protocol-tagged `steps`. Each step calls one protocol (HTTP, DNS, …), every result normalizes into one protocol-blind response shape, and templating, `extract`, and `expect` operate on that shape — never on the protocol. State threads forward: a value a step pulls with `extract` becomes a `{{ }}` variable later steps resolve against.

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

vars:
  tenant: "alpha"

steps:
  - name: fetch-user
    http:
      method: GET
      url: "{{vars.api_base}}/v1/users/{{vars.tenant}}"
      headers:
        authorization: "Bearer {{secrets.api_token}}"
        x-request-id: "{{uuid}}"
    extract:
      user_id: "body:/id"
    expect:
      status: 200

  - name: confirm-user
    http:
      method: GET
      url: "{{vars.api_base}}/v1/users/{{user_id}}"
      headers:
        authorization: "Bearer {{secrets.api_token}}"
    expect:
      status: 200
      body_eq:
        path: "body:/id"
        value: "{{user_id}}"

  - name: dot-query
    dns:
      target: "{{vars.resolver}}"
      tls:
        sni: "cloudflare-dns.com"
        alpn: ["dot"]
      qname: "{{vars.tenant}}.example.com"
      qtype: A
      edns0:
        udp_size: 1232
        options:
          - code: 65184
            payload_hex: "cafe"
    expect:
      status: 200
```

## Step Vocabulary

Each step sets a `name` and exactly one protocol key (`http`, `dns`, …) that selects the adapter. Two optional blocks operate on the normalized response:

- `extract` maps a new variable name to a selector. Selectors match the assertion selectors: `status`, `header:<name>`, and `body:<path>` (an RFC 6901 JSON pointer such as `body:/data/0/id`, or the dotted sugar `body:data.0.id`). An extracted value is bound bare, so a later step resolves it as `{{ name }}`.
- `expect` asserts on the response: `status` (a single code or a list of accepted codes) and/or `body_eq` (`path` + expected `value`). A failed `expect` fails the step.

Load experiments run scenarios at controlled or aggressive scale. A scenario-load run drives many workers through the same step chain and reports per-step latency, error, and throughput; the ladder schedule (climb dimension, interval, stop rules, cool-down) is configured on the load run, not embedded in the scenario file.

## Compilation Boundary

Before execution, the compiler:

1. Parses with an established serialization library and rejects unknown or invalid fields.
2. Resolves the profile and validates all variable and secret references.
3. Checks protocol-step compatibility and connection policy.
4. Resolves target safety policy without exposing secret values.
5. Indexes corpora and creates immutable run inputs.
6. Produces a deterministic plan with a scenario hash and random seed.

No YAML parsing, template expansion, schema lookup, or keychain access belongs on the traffic hot path.

## Versioning Rules

- `version` is required and changes only for incompatible schema changes.
- Unknown fields are errors by default so misspellings do not silently alter traffic.
- Stable formatting keeps diffs reviewable.
- Generated JSON Schema is derived from the same Rust domain types used by the compiler.
- Report snapshots record the schema version, scenario hash, resolved non-secret configuration, and Git state.
