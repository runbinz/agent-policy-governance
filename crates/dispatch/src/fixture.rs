//! In-memory provider fixture for local integration and failure tests.
//! This adapter never sends network requests. Clones share the simulated provider.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use tokio::sync::watch;

use crate::{
    EvidenceRef, ProviderKey, ProviderOutcome, RefundProvider, ReplaySafety, VerifiedRefundRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureScenario {
    Success,
    AcceptedThenTimeout,
    Pending,
    ConfirmedNonExecution,
}

#[derive(Clone)]
pub struct FixtureProvider {
    shared: Arc<Shared>,
    replay: ReplaySafety,
}

struct Shared {
    state: Mutex<State>,
    paused: watch::Sender<bool>,
    executes: watch::Sender<usize>,
}

struct State {
    scenario: FixtureScenario,
    payments: HashMap<String, FixturePayment>,
    execute_count: usize,
    reconcile_count: usize,
}

struct FixturePayment {
    request: VerifiedRefundRequest,
    outcome: ProviderOutcome,
}

impl FixtureProvider {
    pub fn new(scenario: FixtureScenario) -> Self {
        Self::with_replay_safety(scenario, ReplaySafety::ReconcileOnly)
    }

    pub fn with_replay_safety(scenario: FixtureScenario, replay: ReplaySafety) -> Self {
        Self {
            replay,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    scenario,
                    payments: HashMap::new(),
                    execute_count: 0,
                    reconcile_count: 0,
                }),
                paused: watch::channel(false).0,
                executes: watch::channel(0).0,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Affects only requests with keys the fixture has never seen.
    pub fn set_scenario(&self, scenario: FixtureScenario) {
        self.state().scenario = scenario;
    }

    /// Counts accepted refunds, including provider-pending refunds.
    pub fn effect_count(&self) -> usize {
        self.state()
            .payments
            .values()
            .filter(|payment| {
                matches!(
                    payment.outcome,
                    ProviderOutcome::ConfirmedSuccess(_) | ProviderOutcome::Pending
                )
            })
            .count()
    }

    pub fn execute_count(&self) -> usize {
        self.state().execute_count
    }

    pub fn reconcile_count(&self) -> usize {
        self.state().reconcile_count
    }

    /// Resolves every pending fixture payment and returns the number resolved.
    pub fn complete_pending(&self) -> usize {
        let mut state = self.state();
        let mut changed = 0;
        for (key, payment) in &mut state.payments {
            if payment.outcome == ProviderOutcome::Pending {
                payment.outcome = succeeded(key);
                changed += 1;
            }
        }
        changed
    }

    /// Blocks execution responses after recording their effects; reconciliation
    /// stays available. Canceling the caller will not undo an accepted effect.
    pub fn pause_responses(&self) {
        self.shared.paused.send_replace(true);
    }

    pub fn resume_responses(&self) {
        self.shared.paused.send_replace(false);
    }

    pub async fn wait_for_execute_count(&self, minimum: usize) {
        // This receiver cannot observe a closed channel while self is alive.
        let _ = self
            .shared
            .executes
            .subscribe()
            .wait_for(|&count| count >= minimum)
            .await;
    }

    async fn wait_for_response(&self) {
        let _ = self
            .shared
            .paused
            .subscribe()
            .wait_for(|&paused| !paused)
            .await;
    }
}

fn succeeded(key: &str) -> ProviderOutcome {
    ProviderOutcome::ConfirmedSuccess(EvidenceRef(format!("fixture-success:{key}")))
}

impl RefundProvider for FixtureProvider {
    fn replay_safety(&self) -> ReplaySafety {
        self.replay
    }

    async fn execute(&self, request: &VerifiedRefundRequest, key: &ProviderKey) -> ProviderOutcome {
        let outcome = {
            let mut state = self.state();
            let key = key.as_str();
            let outcome = if let Some(stored) = state.payments.get(key) {
                if &stored.request == request {
                    stored.outcome.clone()
                } else {
                    ProviderOutcome::Unknown
                }
            } else {
                let stored = match state.scenario {
                    FixtureScenario::Success | FixtureScenario::AcceptedThenTimeout => {
                        succeeded(key)
                    }
                    FixtureScenario::Pending => ProviderOutcome::Pending,
                    FixtureScenario::ConfirmedNonExecution => {
                        ProviderOutcome::ConfirmedNonExecution(EvidenceRef(format!(
                            "fixture-no-effect:{key}"
                        )))
                    }
                };
                let returned = if state.scenario == FixtureScenario::AcceptedThenTimeout {
                    ProviderOutcome::Unknown
                } else {
                    stored.clone()
                };
                state.payments.insert(
                    key.to_owned(),
                    FixturePayment {
                        request: request.clone(),
                        outcome: stored,
                    },
                );
                returned
            };
            state.execute_count += 1;
            self.shared.executes.send_replace(state.execute_count);
            outcome
        };
        self.wait_for_response().await;
        outcome
    }

    async fn reconcile(
        &self,
        request: &VerifiedRefundRequest,
        key: &ProviderKey,
    ) -> ProviderOutcome {
        let mut state = self.state();
        state.reconcile_count += 1;
        state
            .payments
            .get(key.as_str())
            .filter(|payment| &payment.request == request)
            .map_or(ProviderOutcome::Unknown, |payment| payment.outcome.clone())
    }
}
