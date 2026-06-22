# Desktop UI Plan

This plan turns the static shell in `apps/web` into a local-first desktop UI.
Yaak is the interaction reference: a quiet request tree, a focused editor, and a
response inspector that keeps common actions visible without exposing every
setting at once. WireSurge keeps its own identity and adds runner and load-test
observability as first-class surfaces.

## Product Decision

Build the first usable desktop slice around behavior the repository supports
today:

- Open one local `.wiresurge` workspace.
- List, create, rename, edit, duplicate, and delete flat HTTP requests.
- Send one HTTP request and inspect its status, duration, headers, body, and
  warnings.
- Read runner snapshots and report summaries.
- Show clear empty, loading, saved, running, error, cancelled, and stale states.

Do not expose folders, environments, auth helpers, workflow graphs, live charts,
or reusable DNS load profiles until their domain models and IPC contracts exist.
Disabled placeholder controls create a larger interface without making the
product more useful.

The initial UI is desktop-first. A browser build can render the same components
with a fixture or read-only adapter, but arbitrary HTTP, DNS, TLS, and raw
transport execution remains a native capability.

## Reference Principles

Borrow these interaction patterns from Yaak:

- Keep workspace resources in a persistent left sidebar.
- Put method, URL, and Send on one high-priority row.
- Use tabs for secondary request and response details.
- Reveal advanced controls only where they are relevant.
- Prefer keyboard shortcuts, inline editing, and automatic persistence over
  modal-heavy flows.
- Keep status, duration, and response size close to the response body.

Do not copy Yaak's branding, exact layout measurements, icons, theme, or full
feature set. WireSurge needs a distinct runner/report model and a visibly safer
path into traffic generation.

Primary references:

- [Yaak project and feature overview](https://github.com/mountain-loop/yaak)
- [Yaak HTTP request documentation](https://yaak.app/docs/request-types/http-requests)
- [Yaak sidebar filtering release](https://yaak.app/changelog/2025.8.0)
- [Yaak request debugging and timeline release](https://yaak.app/changelog/2026.1.0)
- [Tauri Vite integration](https://v2.tauri.app/start/frontend/vite/)

## Information Architecture

Use a three-region application shell rather than the current page of stacked
cards:

```text
+---------+----------------------+-------------------------------------------+
| Rail    | Resource sidebar     | Active workspace                          |
|         |                      |                                           |
| Request | Workspace name       | Request name                 Saved        |
| Runners | Filter requests      | [GET] [https://...]          [Send]       |
| Reports | + New request        |                                           |
|         |                      | Request        | Response                 |
|         | GET Health           | Body Headers   | Body Headers             |
|         | POST Create user     |                | 200  12 ms  1.2 KB       |
|         |                      |                |                           |
| Settings| Engine status        | Resizable editor and inspector panes      |
+---------+----------------------+-------------------------------------------+
```

### Utility rail

The narrow rail switches between Requests, Runners, and Reports. Settings stays
at the bottom. Git should not appear until Git state and actions are actually
implemented.

### Resource sidebar

The sidebar changes with the active surface:

- **Requests:** filter, add action, and the flat request list supported by
  `RequestSpec` today. Use colored method labels and the request name.
- **Runners:** active, idle, stale, and stopped processes sorted by health and
  last heartbeat.
- **Reports:** recent reports grouped by date with status and duration.

The sidebar is resizable and collapsible. Persist its width locally, not in the
workspace.

### Active workspace

Only the active task occupies the main area. A request view contains the request
composer and response inspector. Runner and report views use list/detail layouts
rather than being appended below the request editor.

## Request Workspace

### Header and send row

- Edit the request name inline.
- Keep method, URL, and Send on one row.
- Validate the URL before sending and map backend error `path` values to the
  relevant field.
- Use `Cmd/Ctrl+Enter` to send and `Cmd/Ctrl+S` to flush pending saves.
- While a request is in flight, replace Send with Cancel when cancellation is
  supported by IPC. Until then, show a spinner and prevent duplicate sends.

### Request tabs

The first release needs only tabs backed by `RequestSpec`:

- **Body:** plain text editor with a format hint inferred from `content-type`.
- **Headers:** editable key/value rows with add, remove, and duplicate-key
  validation.

Params, Auth, Cookies, Scripts, and Settings remain out of the UI until the core
request schema can represent them. Query parameters can still be edited in the
URL.

Start with native inputs and a well-styled text area. Add a code editor only
after body editing, selection, undo, large payloads, and accessibility are tested;
the editor should not block the first functional slice.

### Persistence

- Save valid changes after a short debounce.
- Show `Saving`, `Saved`, or `Save failed` beside the request name.
- Keep the last valid server copy when an edit is temporarily invalid.
- Flush pending changes before Send.
- Confirm only destructive actions such as delete; creation and rename stay
  inline.

## Response Inspector

Render only fields currently produced by `HttpResponse`:

- Status code and reason.
- Duration.
- Body byte size, computed in the UI until it becomes part of the response
  contract.
- Response body.
- Response headers.
- Warnings, including the current redirect-following warning.

The first response tabs are **Body** and **Headers**. Pretty-print valid JSON but
retain a Raw toggle so the original text remains inspectable. Do not advertise a
network timeline until the engine records DNS, connect, TLS, request, and
response phases.

Keep the last response visible while a new request runs, but mark it as the
previous result. On failure, show the structured error without discarding the
last successful response.

## Runners And Reports

### Runners

The current `RunnerStats` model supports a useful snapshot view:

- Health, source, PID, version, and last heartbeat.
- Active run ID.
- QPS/RPS, p50/p95/p99, errors, timeouts, connections, CPU, and memory.
- Per-worker status and the same core traffic metrics.

Treat a runner as stale when its heartbeat crosses a backend-defined threshold;
do not hardcode process-liveness semantics in React. Polling snapshots is
acceptable for the first read-only view. Stop, Terminate, and Kill remain hidden
until the supervised engine implements their escalation contract.

### Reports

The report detail view can show status, start time, duration, request/error
counts, p50/p95/p99, error summary, Git commit, and redaction status. The first
release is read-only. Export and comparison wait for stable backend operations.

### DNS and load testing

The existing `wiresurge load` command is not yet a persisted desktop resource.
It can publish process-local `RunSnapshot` values and returns final `LoadStats`,
but neither contract is exposed through sidecar IPC. Add a Load surface only
after introducing:

- A versioned `LoadProfile` that can represent protocol, target, corpus, QPS,
  connection count, in-flight depth, timeout, count/duration, and safety limits.
- Validation and redaction shared by CLI and desktop.
- IPC progress events that wrap the existing monotonic counters with stable run
  IDs, sequence numbers, and timestamps.
- Cooperative cancel and bounded drain commands.

When ready, the load composer should reuse the request workspace pattern: a
small target row, progressive protocol settings, an explicit traffic summary,
and a separate live results pane. Public-target confirmation must be part of the
flow, not a generic warning banner.

## Frontend Structure

Evolve `apps/web` into the shared React and TypeScript application. Keep the
Tauri host in `apps/desktop/src-tauri` and point it at the Vite development server
and production bundle.

Suggested source boundaries:

```text
apps/web/
  src/
    app/              routing, providers, error boundary, shortcuts
    components/       reusable visual primitives
    features/
      requests/       list, editor, headers, response inspector
      runners/        snapshot list and runner details
      reports/        report list and report details
      workspace/      open/init and workspace header
    lib/
      backend.ts      typed backend interface
      errors.ts       structured error mapping
      formatting.ts   bytes, duration, timestamps, JSON
    styles/           tokens, theme, layout, component styles
apps/desktop/
  src-tauri/          native shell, sidecar lifecycle, capabilities
```

Keep feature components independent of Tauri imports. All native operations go
through a typed `Backend` interface so component tests can use an in-memory
adapter and the browser build can fail clearly for native-only actions.

Avoid a broad component library in the first slice. Build a small set of
accessible primitives needed by this UI: Button, IconButton, Input, Tabs,
SplitPane, Menu, Dialog, Toast, StatusBadge, and key/value rows. Reassess a
library only when repeated behavior makes local ownership more expensive.

## Native Boundary

The target architecture keeps sockets and mutable engine resources out of the
webview. The desktop starts the packaged `wiresurge` sidecar and speaks a
versioned local IPC protocol.

Minimum request/response operations:

```text
workspace.get
request.list
request.create
request.update
request.delete
run.start
run.cancel
runner.list
report.list
report.get
```

Minimum events:

```text
run.started
run.completed
run.failed
runner.updated
engine.status_changed
```

Every message needs a protocol version, request ID, operation, typed payload,
and the existing structured error envelope. Events need a monotonically
increasing sequence number so the UI can detect gaps and request a fresh
snapshot.

Do not make the UI parse human CLI output or repeatedly spawn one CLI process per
action. A temporary fixture adapter is preferable to committing an unstable
process-per-command integration.

## Visual System

The interface should feel compact and calm rather than card-heavy:

- Neutral surfaces separated primarily by one-pixel borders.
- One restrained accent color for selection and primary actions.
- Semantic colors reserved for success, warning, error, and runner health.
- An 8 px spacing grid, 6 px control radius, and compact 32-36 px controls.
- System UI font for controls and a system monospace stack for payloads.
- Light and dark themes driven by semantic CSS custom properties.
- Minimal shadows, used for floating menus and dialogs only.

Design at 1440 x 900 first, verify at 1024 x 700, and provide a single-column
fallback below 800 px. At narrower widths, the response inspector moves below
the request editor and the resource sidebar becomes an overlay.

## Interaction And Accessibility Contract

- All actions are reachable by keyboard and show a visible focus indicator.
- Tabs use correct tab/list semantics and arrow-key navigation.
- Pane resizing has keyboard controls and reasonable min/max widths.
- Status never relies on color alone.
- Toasts announce non-blocking results; field errors stay beside their fields.
- Destructive confirmation returns focus to the initiating control when closed.
- Respect reduced motion and operating-system light/dark preference.
- Large or unformatted bodies must not freeze the webview; cap automatic JSON
  formatting and provide a Raw fallback.

## Delivery Milestones

### 0. Contracts and scaffold

- Convert `apps/web` to Vite, React, and TypeScript.
- Add the Tauri shell under `apps/desktop/src-tauri`.
- Define TypeScript domain types and the `Backend` interface.
- Add fixture data for all primary UI states.
- Establish lint, type-check, unit-test, and production-build commands.

Done when the desktop and browser fixture build render the same application
shell with no engine dependency.

### 1. Request workspace

- Build the utility rail, resizable resource sidebar, request list, editor, and
  response inspector.
- Implement create, update, delete, validation, save state, and request filtering
  against the fixture backend.
- Add keyboard shortcuts and empty/error states.

Done when a user can complete the full request editing flow using mouse or
keyboard and component tests cover each state transition.

### 2. Engine IPC and HTTP execution

- Add internal sidecar mode and versioned IPC.
- Wire workspace/request CRUD and `run.start` to existing Rust libraries.
- Stream completion/failure events and implement cancellation.
- Map `WireSurgeError.path` to fields and preserve redaction.

Done when a stored request can be edited, sent, cancelled, and inspected without
the UI reading files directly or parsing terminal text.

### 3. Runners and reports

- Add runner list/detail and stale-state handling.
- Add report list/detail.
- Replace polling after runner updates and the existing load snapshot stream are
  exposed through versioned IPC events.

Done when UI values match `runner --output json` and `report --output json`
fixtures and refresh correctly after a run.

### 4. Load workspace

- Add the versioned load-profile model and safety policy in Rust.
- Expose the current load snapshots through bounded IPC events and add
  cancellation lifecycle events.
- Build the DNS/DoT/DoH load composer and results view.

Done when a user can review the exact target and traffic budget before starting,
observe a run without unbounded rendering work, and stop it through the shared
shutdown state machine.

## Test Strategy

- **Rust contract tests:** serialize every IPC response/event and structured
  error; reject incompatible protocol versions.
- **Frontend unit tests:** reducers, formatting, validation mapping, stale-runner
  classification, and backend adapters.
- **Component tests:** request editing, save failures, send/cancel states,
  response tabs, keyboard navigation, and destructive confirmations.
- **Desktop integration tests:** sidecar start, workspace open, CRUD, run,
  cancellation, crash, and reconnect.
- **Visual checks:** light/dark themes at 1440 x 900, 1024 x 700, and the narrow
  fallback, including long names and large metrics.
- **Performance checks:** 500 request rows, a 16 MiB response, rapid runner
  updates, and a stale or disconnected sidecar.

## Backend Work Required Before Live Wiring

The UI can be built against fixtures now. Live integration should wait for these
contracts:

1. Versioned sidecar IPC and lifecycle ownership.
2. Stable request CRUD operations that return unredacted values only to the
   authorized local editor while preserving redaction in logs and reports.
3. Run IDs and cancellation handles that outlive a single command call.
4. Atomic runner/report reads and a documented stale-heartbeat threshold.
5. An IPC adapter for current load snapshots, adding timestamps, run IDs, and
   sequence numbers for charts and reconnect recovery.
6. A persisted, validated load-profile model before exposing load configuration.

## First Implementation Slice

The next code change should complete Milestone 0 only. It should establish the
React/Tauri build, semantic tokens, application shell, typed backend interface,
and fixture states. It should not add a code editor, charting package, component
framework, or ad hoc CLI spawning. That keeps the first review focused on the
architecture and interaction foundation that every later screen will use.
