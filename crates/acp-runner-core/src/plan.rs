//! Retry / fallback planner.
//!
//! Policy (deliberately simple and explicit):
//!
//! ```text
//! classes = [primary, fallback_1, ...]
//! for each class: up to retry.maxAttemptsPerRunner attempts
//! a failure whose disposition is SkipToFallback moves to the next class immediately
//! a Fatal failure (cancellation) stops the run
//! retry.maxTotalAttempts (optional) caps everything
//! ```
//!
//! Example with `maxAttemptsPerRunner: 2`, classes `[claude, codex]`:
//!
//! ```text
//! claude attempt 1 -> claude attempt 2 -> codex attempt 1 -> codex attempt 2 -> RunFailed
//! ```

use crate::failure::RetryDisposition;
use crate::spec::RetryPolicy;
use serde::{Deserialize, Serialize};

/// What the planner needs to know about a finished attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishedAttempt {
    pub class_index: usize,
    pub disposition: RetryDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextAttempt {
    pub class_index: usize,
    /// 1-based attempt number within the runner class.
    pub class_attempt: u32,
    /// 1-based attempt number within the run.
    pub ordinal: u32,
    /// True when this attempt switches to a different runner class than the previous one.
    pub is_fallback: bool,
}

/// Decide the next attempt given the history of *finished, failed* attempts (in order).
/// Returns `None` when the policy is exhausted.
pub fn plan_next(num_classes: usize, retry: &RetryPolicy, history: &[FinishedAttempt]) -> Option<NextAttempt> {
    if num_classes == 0 {
        return None;
    }
    let max_per = retry.max_attempts_per_runner.max(1);
    let total = history.len() as u32;
    if let Some(cap) = retry.max_total_attempts
        && total >= cap
    {
        return None;
    }
    let Some(last) = history.last() else {
        return Some(NextAttempt { class_index: 0, class_attempt: 1, ordinal: 1, is_fallback: false });
    };
    if last.disposition == RetryDisposition::Fatal {
        return None;
    }
    let mut class_index = last.class_index;
    let mut used_in_class = history.iter().filter(|h| h.class_index == class_index).count() as u32;
    if last.disposition == RetryDisposition::SkipToFallback || used_in_class >= max_per {
        class_index += 1;
        used_in_class = history.iter().filter(|h| h.class_index == class_index).count() as u32;
    }
    if class_index >= num_classes {
        return None;
    }
    Some(NextAttempt {
        class_index,
        class_attempt: used_in_class + 1,
        ordinal: total + 1,
        is_fallback: class_index != last.class_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use RetryDisposition::*;

    fn f(class_index: usize, disposition: RetryDisposition) -> FinishedAttempt {
        FinishedAttempt { class_index, disposition }
    }

    #[test]
    fn claude_twice_then_codex_once() {
        let retry = RetryPolicy { max_attempts_per_runner: 2, max_total_attempts: None };
        let mut h = vec![];
        let n1 = plan_next(2, &retry, &h).unwrap();
        assert_eq!((n1.class_index, n1.class_attempt, n1.ordinal, n1.is_fallback), (0, 1, 1, false));
        h.push(f(0, RetrySame));
        let n2 = plan_next(2, &retry, &h).unwrap();
        assert_eq!((n2.class_index, n2.class_attempt, n2.ordinal, n2.is_fallback), (0, 2, 2, false));
        h.push(f(0, RetrySame));
        let n3 = plan_next(2, &retry, &h).unwrap();
        assert_eq!((n3.class_index, n3.class_attempt, n3.ordinal, n3.is_fallback), (1, 1, 3, true));
        h.push(f(1, RetrySame));
        let n4 = plan_next(2, &retry, &h).unwrap();
        assert_eq!((n4.class_index, n4.class_attempt, n4.ordinal), (1, 2, 4));
        h.push(f(1, RetrySame));
        assert!(plan_next(2, &retry, &h).is_none());
    }

    #[test]
    fn auth_failure_skips_remaining_retries() {
        let retry = RetryPolicy { max_attempts_per_runner: 3, max_total_attempts: None };
        let h = vec![f(0, SkipToFallback)];
        let n = plan_next(2, &retry, &h).unwrap();
        assert_eq!((n.class_index, n.class_attempt, n.is_fallback), (1, 1, true));
        let h = vec![f(0, SkipToFallback), f(1, SkipToFallback)];
        assert!(plan_next(2, &retry, &h).is_none());
    }

    #[test]
    fn fatal_stops() {
        let retry = RetryPolicy { max_attempts_per_runner: 3, max_total_attempts: None };
        assert!(plan_next(2, &retry, &[f(0, Fatal)]).is_none());
    }

    #[test]
    fn total_cap() {
        let retry = RetryPolicy { max_attempts_per_runner: 5, max_total_attempts: Some(2) };
        assert!(plan_next(1, &retry, &[f(0, RetrySame)]).is_some());
        assert!(plan_next(1, &retry, &[f(0, RetrySame), f(0, RetrySame)]).is_none());
    }

    #[test]
    fn single_class_single_attempt() {
        let retry = RetryPolicy::default();
        assert!(plan_next(1, &retry, &[f(0, RetrySame)]).is_none());
    }
}
