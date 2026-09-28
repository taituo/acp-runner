//! Test helpers: throw-away databases.
//!
//! Integration tests that need PostgreSQL read `ACP_TEST_DATABASE_URL` (an admin-capable
//! URL, e.g. `postgres://acp@127.0.0.1:55432/postgres`) and create a uniquely named
//! database per test. When the variable is unset the tests are skipped with a message.

use crate::Journal;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Executor};
use std::str::FromStr;

pub struct TempDb {
    pub journal: Journal,
    pub name: String,
    pub url: String,
    admin: PgConnectOptions,
}

impl TempDb {
    pub async fn drop_db(self) {
        self.journal.pool().close().await;
        if let Ok(mut c) = self.admin.connect().await {
            let _ = c.execute(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name))).await;
        }
    }
}

pub async fn temp_database() -> Option<TempDb> {
    let Ok(url) = std::env::var("ACP_TEST_DATABASE_URL") else {
        if std::env::var("ACP_REQUIRE_DB_TESTS").as_deref() == Ok("1") {
            panic!("ACP_TEST_DATABASE_URL is required when ACP_REQUIRE_DB_TESTS=1 (refusing to SKIP)");
        }
        eprintln!("SKIPPED: set ACP_TEST_DATABASE_URL to run PostgreSQL-backed tests");
        return None;
    };
    let admin = PgConnectOptions::from_str(&url).expect("valid ACP_TEST_DATABASE_URL");
    let name = format!("acp_test_{}", uuid::Uuid::new_v4().simple());
    let mut c = admin.connect().await.expect("connect admin");
    c.execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).await.expect("create db");
    let opts = admin.clone().database(&name);
    let pool = PgPoolOptions::new().max_connections(8).connect_with(opts).await.expect("connect test db");
    let journal = Journal::from_pool(pool);
    journal.migrate().await.expect("migrate");
    let db_url = match url.rsplit_once('/') {
        Some((base, _)) => format!("{base}/{name}"),
        None => url.clone(),
    };
    Some(TempDb { journal, name, url: db_url, admin })
}
