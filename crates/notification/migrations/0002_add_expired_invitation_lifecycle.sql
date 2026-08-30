ALTER TABLE notification.source_lifecycle_events
    DROP CONSTRAINT notification_source_lifecycle;

ALTER TABLE notification.source_lifecycle_events
    ADD CONSTRAINT notification_source_lifecycle
    CHECK (lifecycle IN ('accepted', 'expired', 'revoked'));
