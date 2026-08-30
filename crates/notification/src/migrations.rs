use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

pub const NOTIFICATION_MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-notification-schema",
        "migrations/0001_create_notification_schema.sql",
    ),
    (
        2,
        "add-expired-invitation-lifecycle",
        "migrations/0002_add_expired_invitation_lifecycle.sql",
    ),
];

pub fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, NOTIFICATION_MIGRATIONS)
}
