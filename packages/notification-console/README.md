# Notification Console artifact

This package preserves the Deliveries UI build only. It is not registered by
`lenso.notification` and is not reachable in a vNext App today.

A future, separately removable Adapter must require
`lenso.notification.admin@1`, provide `lenso.http.endpoint@1`, and bind this
artifact only after `lenso-web` aligns to the same Lenso dependency revisions.
The OpenAPI document in `src/` describes the retained UI adapter shape; it is
not a Capability owned by the core Notification Plugin and is not proof that an
HTTP endpoint exists.
