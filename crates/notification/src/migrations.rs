use lenso::host::Migration;

pub const NOTIFICATION_MIGRATIONS: &[Migration] = &[Migration {
    name: "notification/0001_create_notification_schema",
    sql: include_str!("../migrations/0001_create_notification_schema.sql"),
}];
