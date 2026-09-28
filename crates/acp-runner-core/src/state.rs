//! Explicit state machines for runs and attempts.
//!
//! A *Run* is the stable, logical unit requested by the orchestrator. An *Attempt* is one
//! disposable execution of that run on one runner class inside one sandbox. A run owns an
//! ordered list of attempts; at most one attempt is active at a time.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RunPhase {
    /// Known to the engine, no attempt started yet (or waiting for a credential lease).
    Pending,
    /// An attempt is active or the next attempt is being planned.
    Running,
    /// An attempt completed successfully and produced the expected output.
    Succeeded,
    /// All attempts permitted by the retry/fallback policy failed.
    Failed,
    /// The run was cancelled (resource deleted or `spec.cancel=true`).
    Cancelled,
}

impl RunPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, RunPhase::Succeeded | RunPhase::Failed | RunPhase::Cancelled)
    }

    /// Allowed transitions. Terminal phases are absorbing.
    pub fn can_transition_to(self, next: RunPhase) -> bool {
        use RunPhase::*;
        if self == next {
            return true;
        }
        match self {
            Pending => matches!(next, Running | Failed | Cancelled),
            Running => matches!(next, Pending | Succeeded | Failed | Cancelled),
            Succeeded | Failed | Cancelled => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RunPhase::Pending => "Pending",
            RunPhase::Running => "Running",
            RunPhase::Succeeded => "Succeeded",
            RunPhase::Failed => "Failed",
            RunPhase::Cancelled => "Cancelled",
        }
    }
}

impl fmt::Display for RunPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RunPhase {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Pending" => RunPhase::Pending,
            "Running" => RunPhase::Running,
            "Succeeded" => RunPhase::Succeeded,
            "Failed" => RunPhase::Failed,
            "Cancelled" => RunPhase::Cancelled,
            other => return Err(format!("unknown run phase {other:?}")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttemptPhase {
    /// Row exists; sandbox not (yet) created.
    Pending,
    /// Sandbox created; runnerd has not reported the agent process yet.
    Starting,
    /// runnerd reported the agent process started.
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

impl AttemptPhase {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AttemptPhase::Succeeded | AttemptPhase::Failed | AttemptPhase::TimedOut | AttemptPhase::Cancelled
        )
    }

    pub fn is_active(self) -> bool {
        !self.is_terminal()
    }

    pub fn can_transition_to(self, next: AttemptPhase) -> bool {
        use AttemptPhase::*;
        if self == next {
            return true;
        }
        match self {
            Pending => matches!(next, Starting | Failed | TimedOut | Cancelled),
            Starting => matches!(next, Running | Succeeded | Failed | TimedOut | Cancelled),
            Running => matches!(next, Succeeded | Failed | TimedOut | Cancelled),
            Succeeded | Failed | TimedOut | Cancelled => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AttemptPhase::Pending => "Pending",
            AttemptPhase::Starting => "Starting",
            AttemptPhase::Running => "Running",
            AttemptPhase::Succeeded => "Succeeded",
            AttemptPhase::Failed => "Failed",
            AttemptPhase::TimedOut => "TimedOut",
            AttemptPhase::Cancelled => "Cancelled",
        }
    }

    pub const ACTIVE: [AttemptPhase; 3] = [AttemptPhase::Pending, AttemptPhase::Starting, AttemptPhase::Running];
}

impl fmt::Display for AttemptPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AttemptPhase {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Pending" => AttemptPhase::Pending,
            "Starting" => AttemptPhase::Starting,
            "Running" => AttemptPhase::Running,
            "Succeeded" => AttemptPhase::Succeeded,
            "Failed" => AttemptPhase::Failed,
            "TimedOut" => AttemptPhase::TimedOut,
            "Cancelled" => AttemptPhase::Cancelled,
            other => return Err(format!("unknown attempt phase {other:?}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_phases_are_absorbing() {
        for p in [RunPhase::Succeeded, RunPhase::Failed, RunPhase::Cancelled] {
            assert!(p.is_terminal());
            assert!(!p.can_transition_to(RunPhase::Running));
            assert!(p.can_transition_to(p));
        }
        for p in [AttemptPhase::Succeeded, AttemptPhase::Failed, AttemptPhase::TimedOut, AttemptPhase::Cancelled] {
            assert!(p.is_terminal());
            assert!(!p.can_transition_to(AttemptPhase::Running));
        }
    }

    #[test]
    fn attempt_lifecycle_happy_path() {
        use AttemptPhase::*;
        assert!(Pending.can_transition_to(Starting));
        assert!(Starting.can_transition_to(Running));
        assert!(Running.can_transition_to(Succeeded));
        assert!(!Succeeded.can_transition_to(Failed));
        assert!(!Running.can_transition_to(Pending));
    }

    #[test]
    fn roundtrip_strings() {
        for p in [RunPhase::Pending, RunPhase::Running, RunPhase::Succeeded, RunPhase::Failed, RunPhase::Cancelled] {
            assert_eq!(p.as_str().parse::<RunPhase>().unwrap(), p);
        }
        for p in [
            AttemptPhase::Pending,
            AttemptPhase::Starting,
            AttemptPhase::Running,
            AttemptPhase::Succeeded,
            AttemptPhase::Failed,
            AttemptPhase::TimedOut,
            AttemptPhase::Cancelled,
        ] {
            assert_eq!(p.as_str().parse::<AttemptPhase>().unwrap(), p);
        }
    }
}
