//! Prometheus metrics.
//!
//! Labels are deliberately low-cardinality (`driver`, `runner_class`, `reason`). Run and
//! attempt identifiers are carried by structured logs and the journal, not by metric labels.
//! No label ever carries credential material.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

type Labels = Vec<(String, String)>;

pub struct Metrics {
    registry: Registry,
    pub runs_total: Family<Labels, Counter>,
    pub attempts_total: Family<Labels, Counter>,
    pub attempt_duration_seconds: Family<Labels, Histogram>,
    pub attempt_failures_total: Family<Labels, Counter>,
    pub active_attempts: Family<Labels, Gauge>,
    pub timeouts_total: Family<Labels, Counter>,
    pub fallbacks_total: Family<Labels, Counter>,
    pub credential_writebacks_total: Family<Labels, Counter>,
}

fn l(pairs: &[(&str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Metrics {
        let mut registry = Registry::with_prefix("acp_runner");
        let runs_total = Family::<Labels, Counter>::default();
        let attempts_total = Family::<Labels, Counter>::default();
        let attempt_duration_seconds =
            Family::<Labels, Histogram>::new_with_constructor(|| Histogram::new(exponential_buckets(1.0, 2.0, 14)));
        let attempt_failures_total = Family::<Labels, Counter>::default();
        let active_attempts = Family::<Labels, Gauge>::default();
        let timeouts_total = Family::<Labels, Counter>::default();
        let fallbacks_total = Family::<Labels, Counter>::default();
        let credential_writebacks_total = Family::<Labels, Counter>::default();
        registry.register("runs", "Runs by result (created, succeeded, failed, cancelled)", runs_total.clone());
        registry.register("attempts", "Attempts started", attempts_total.clone());
        registry.register(
            "attempt_duration_seconds",
            "Wall-clock duration of finished attempts",
            attempt_duration_seconds.clone(),
        );
        registry.register("attempt_failures", "Failed or timed-out attempts by reason", attempt_failures_total.clone());
        registry.register("active_attempts", "Attempts currently Pending/Starting/Running", active_attempts.clone());
        registry.register("timeouts", "Attempt timeouts by kind", timeouts_total.clone());
        registry.register("fallbacks", "Switches to a fallback runner class", fallbacks_total.clone());
        registry.register(
            "credential_writebacks",
            "Refreshed credential write-backs by result",
            credential_writebacks_total.clone(),
        );
        Metrics {
            registry,
            runs_total,
            attempts_total,
            attempt_duration_seconds,
            attempt_failures_total,
            active_attempts,
            timeouts_total,
            fallbacks_total,
            credential_writebacks_total,
        }
    }

    pub fn run(&self, result: &str) {
        self.runs_total.get_or_create(&l(&[("result", result)])).inc();
    }

    pub fn attempt_started(&self, driver: &str, class: &str) {
        self.attempts_total.get_or_create(&l(&[("driver", driver), ("runner_class", class)])).inc();
    }

    pub fn attempt_finished(&self, driver: &str, phase: &str, reason: Option<&str>, timeout: bool, seconds: f64) {
        self.attempt_duration_seconds
            .get_or_create(&l(&[("driver", driver), ("phase", phase)]))
            .observe(seconds.max(0.0));
        if let Some(r) = reason {
            self.attempt_failures_total.get_or_create(&l(&[("driver", driver), ("reason", r)])).inc();
            if timeout {
                self.timeouts_total.get_or_create(&l(&[("driver", driver), ("kind", r)])).inc();
            }
        }
    }

    pub fn fallback(&self, from: &str, to: &str) {
        self.fallbacks_total.get_or_create(&l(&[("from_driver", from), ("to_driver", to)])).inc();
    }

    pub fn writeback(&self, result: &str, reason: &str) {
        self.credential_writebacks_total.get_or_create(&l(&[("result", result), ("reason", reason)])).inc();
    }

    pub fn set_active(&self, counts: &[(String, i64)], known_drivers: &[&str]) {
        for d in known_drivers {
            let n = counts.iter().find(|(k, _)| k == d).map(|(_, n)| *n).unwrap_or(0);
            self.active_attempts.get_or_create(&l(&[("driver", d)])).set(n);
        }
        for (d, n) in counts {
            self.active_attempts.get_or_create(&l(&[("driver", d)])).set(*n);
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = encode(&mut s, &self.registry);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_expected_names() {
        let m = Metrics::new();
        m.run("created");
        m.attempt_started("fake", "fake-default");
        m.attempt_finished("fake", "TimedOut", Some("NoProgressTimeout"), true, 3.0);
        m.fallback("claude", "codex");
        m.set_active(&[("codex".into(), 2)], &["fake", "codex", "claude"]);
        let out = m.render();
        for name in [
            "acp_runner_runs_total",
            "acp_runner_attempts_total",
            "acp_runner_attempt_duration_seconds_bucket",
            "acp_runner_attempt_failures_total",
            "acp_runner_active_attempts",
            "acp_runner_timeouts_total",
            "acp_runner_fallbacks_total",
        ] {
            assert!(out.contains(name), "missing {name} in\n{out}");
        }
    }
}
