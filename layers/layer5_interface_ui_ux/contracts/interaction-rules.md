# Layer 5 Interaction Rules

## Error-State Behavior

These behaviors are mandatory for all screens.

### 401 Unauthorized
- Trigger: session token missing/expired/invalid.
- UI behavior:
  - clear session state
  - redirect to login view
  - show compact banner: `Session expired. Please sign in again.`

### 403 Forbidden
- Trigger: tenant access outside authorized scope.
- UI behavior:
  - stay on current route shell
  - show explicit tenant-scope violation message
  - do not show stale data for unauthorized tenant

### 404 Not Found
- Trigger: cycle/simulation/tenant artifact missing.
- UI behavior:
  - show scoped missing-resource panel
  - preserve surrounding navigation

### 409 Conflict
- Trigger: active-cycle lock conflict or similar operation collision.
- UI behavior:
  - show conflict banner with retry action
  - do not treat as fatal server error

### 500 Server Error
- Trigger: backend execution failure.
- UI behavior:
  - show failure panel with request context
  - keep route shell visible
  - allow retry

### Timeout / Network Failure
- Trigger: client timeout or transport failure.
- UI behavior:
  - keep last-known data visible if available
  - display stale-data indicator with `last_updated`
  - retry control with bounded backoff

## Partial/Unknown Data Rendering

- Backend `unknown` / `not_observed` states must be rendered explicitly.
- Unknown must never be mapped to low severity.
- Unknown style token: `--color-alert-unknown = #4A5568`.

## Motion Rules

- Motion is optional and minimal.
- Allowed:
  - panel expand/collapse (`120-180ms`)
  - tab transition (`<=120ms`)
  - row detail reveal (`<=120ms`)
- Disallowed:
  - continuous decorative motion
  - chart animations that obscure data values
