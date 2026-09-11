# Frontend language and message guide

## Primary language

Inspectra's current product language is English (`en`). New visible frontend
copy, user-facing API details, reports, and documentation aimed at operators
must use English until a complete, reviewed localization system is introduced.
Do not mix partial translations in a form, flow, or report.

## Shared terms

| Term | Meaning in Inspectra |
| --- | --- |
| **Audit** | An operator-requested analysis of an uploaded file or an explicitly authorized target. |
| **Job** | The server-side record that tracks one audit from queued through a terminal state. |
| **Finding** | A review indicator that needs validation; do not call it a confirmed vulnerability without evidence. |
| **Result** | The redacted output attached to a completed or failed job. |
| **Active audit** | A separately gated flow that may create bounded traffic only after its required confirmations. |
| **Unavailable** | The feature is disabled, not configured, or cannot currently be reached; state the next operator action when it is safe to do so. |

Use sentence case for controls and status messages. Keep machine values such as
`queued`, `running`, `completed`, and `failed` distinct from explanatory copy.

## States and errors

Each user-visible state should say what is happening or happened, then provide
a safe next action when one exists. For example: “Unable to complete the
request. Refresh the page and try again.” Do not expose raw client exceptions,
network traces, target values, credentials, or unredacted backend internals in
fallback errors. Controlled API details may be shown only when the backend
contract already redacts them.

New asynchronous UI work should cover loading, success, empty, unavailable,
and error states in its tests. Error copy should be concise, name the failed
action, and avoid implying that an audit finding is a confirmed vulnerability.
