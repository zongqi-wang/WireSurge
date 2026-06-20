# WireSurge

WireSurge is a local-first desktop and CLI application for API exploration, protocol workflows, and high-rate traffic generation. It combines an API request workspace with a controlled load engine and a path toward composable protocol stages.

This book is the canonical source for the project's architecture, current implementation status, policies, and roadmap. It replaces the former duplicate `architecture.html` documents.

## Reading the Book

The published book is available at:

<https://cedwang.dev/WireSurge/>

The source is ordinary Markdown under `docs/`. To render or serve it locally with mdBook 0.5.3:

```sh
mdbook build
mdbook serve --open
```

## Status Vocabulary

The architecture intentionally describes more than the current scaffold implements. Every chapter uses these terms consistently:

- **Current** means the behavior exists in the repository now.
- **Target** means an accepted design direction that is not fully implemented.
- **Open question** means the project has not made the decision yet.

Start with [Current Implementation](current-implementation.md) for shipped behavior. The architecture chapters describe the target system and call out major gaps.

## Product Boundary

WireSurge is a programmable traffic workbench for systems the operator owns or is authorized to test. The UI helps people design and inspect flows; the engine runs those flows at controlled or aggressive scale. The product is not a hosted traffic service and its core behavior does not require an account, cloud connection, or telemetry.
