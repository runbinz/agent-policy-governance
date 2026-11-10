# Approval notification transport

`Notifier` receives only a notification UUID, action UUID, and approval
generation. It sends fixed plain-text facts plus a structural rich-text link to
the configured authenticated reviewer queue, with a plain-text fallback.
Refund amounts, payments, request metadata,
approval digests, and approval buttons are never part of this interface.

With no notification configuration, the transport is disabled. Stray settings cause
startup to fail. Enable one explicit mode:

- `APL_NOTIFICATION_MODE=fake` requires `APL_LOCAL_DEV=true`,
  `APL_NOTIFICATION_ROUTE_ID`, and `APL_CONSOLE_ORIGIN`. This sink performs no
  network calls; the worker records its receipt. Tests can use
  `Notifier::fake` without modifying process environment.
- `APL_NOTIFICATION_MODE=slack` also requires `APL_SLACK_TEAM_ID` and
  `APL_SLACK_BOT_TOKEN` (a bot token beginning with `xoxb-`).

Use a canonical HTTPS console origin without path, query, user information,
or fragment. Fake mode also accepts HTTP loopback origins. Tokens stay in
zeroizing memory, are not exposed by Debug, and are sent only in the HTTP
Authorization header. Configuration errors never include their values.

The worker supplies the immutable database route's team and channel. Delivery
requires an exact configured team match and a valid channel ID, then checks the
bot token's team using `auth.test` before each post. No startup network call is
made. Slack requests use only the fixed HTTPS Slack API endpoint; redirects,
automatic transport retries, and proxy environment configuration are disabled.
The complete delivery has a five-second deadline and each response is bounded
to 64 KiB. HTTP 429 returns a bounded retry delay; transient or ambiguous results
request a retry. Permanent credential/permission errors stop delivery.

Slack delivery is **at least once**. A stable `client_msg_id` is best-effort
deduplication, not an exactly-once guarantee. A suspended worker can outlive its
database lease after preflight, and a timeout may occur after Slack has posted.
The persistence layer must fence local receipts, bound attempts, coordinate
channel cooldowns, and recheck stale approval state before delivery. Such
checks cannot recall an external notice already in flight.

The crate tests only a private loopback mock and the network-free fake sink.
No real Slack account has been contacted.

[chat.postMessage](https://docs.slack.dev/reference/methods/chat.postMessage/) ·
[auth.test](https://docs.slack.dev/reference/methods/auth.test/) ·
[Slack rate limits](https://docs.slack.dev/apis/web-api/rate-limits/)

The queue link uses Slack's [rich-text link element](https://docs.slack.dev/reference/block-kit/block-elements/link-element/),
not a Markdown link or an interactive approval button.
