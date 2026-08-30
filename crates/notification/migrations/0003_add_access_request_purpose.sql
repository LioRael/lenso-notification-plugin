alter table notification.intents
    drop constraint notification_intent_purpose;

alter table notification.intents
    add constraint notification_intent_purpose check (
        purpose in (
            'transactional.organization_invitation',
            'transactional.access_request'
        )
    );
