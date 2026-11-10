# Stripe sandbox webhook verifier

Construct `WebhookVerifier` from a trusted sandbox endpoint signing secret
(`whsec_…`) and a direct-account or exact connected-account policy. Pass the
unmodified request bytes, the single `Stripe-Signature` header, and server Unix
time. Reject oversized requests at the HTTP boundary as well. The verifier
accepts any matching `v1` signature during Stripe's signing-secret rotation,
checks a maximum five-minute skew in both directions, and rejects live and
organization-scoped events.

[Stripe signature verification](https://docs.stripe.com/webhooks#verify-manually) ·
[Connect event scope](https://docs.stripe.com/connect/webhooks) ·
[Event types](https://docs.stripe.com/api/events/types) ·
[Refund object](https://docs.stripe.com/api/refunds/object)

The returned fields are deliberately small. Persist the event ID with the
trusted endpoint/connection namespace for durable deduplication before
acknowledging it. A refund hint can wake an existing dispatch only when its
account, charge, and correlation agree with stored routing. Metadata remains a
hint: re-fetch provider evidence through the trusted connection, and never
settle, release, or send a refund based on the event snapshot itself. Do not log
the secret, signature, or raw event.
