# Abuse Alerting Baseline

This server emits structured abuse-related events that can be forwarded to log aggregation and alerting tools.

## Event Signals

- `api_key_rejected`
  - Triggered when a request presents an invalid API key.
- `rate_limit_exceeded`
  - Triggered when the requester-wide quota is exceeded.
- `target_quota_exceeded`
  - Triggered when a requester repeatedly targets the same host beyond the target quota.
- `rate_limit_backend_error`
  - Triggered when the distributed limiter backend (Upstash) errors and the server fails open.
- `abuse_alert_threshold_reached`
  - Triggered when a specific abuse signal count crosses threshold within a rolling window.

## Threshold Controls

- `ABUSE_ALERT_THRESHOLD`
  - Default: `25`
  - Meaning: emit `abuse_alert_threshold_reached` every N events for each abuse signal type.
- `ABUSE_ALERT_WINDOW_MS`
  - Default: `600000` (10 minutes)
  - Meaning: rolling window used for abuse signal counts.

## Recommended Initial Alert Rules

1. High urgency
- Alert when `abuse_alert_threshold_reached` fires for:
  - `api_key_rejected`
  - `target_quota_exceeded`
  - `rate_limit_backend_error`

2. Medium urgency
- Alert when `rate_limit_exceeded` volume trends upward across consecutive windows.

3. Operational watch
- Track count distribution by `requesterScope`, `clientIp`, and `targetHost` fields where present.

## Notes

- Limiter-backend failures currently fail open to preserve availability; monitor `rate_limit_backend_error` closely in public deployments.
- For multi-instance deployments, ensure logs are centralized so abuse thresholds can be interpreted across all instances.
