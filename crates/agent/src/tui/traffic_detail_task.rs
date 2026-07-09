use std::collections::BTreeMap;

use super::{
    app::TuiApp,
    traffic::{TrafficDetailLoadRequest, TrafficDetailLoadResult, load_traffic_detail},
};

const MAX_PENDING_TRAFFIC_DETAIL_LOADS: usize = 4;

#[derive(Default)]
pub(super) struct TrafficDetailTaskPool {
    pending: BTreeMap<u64, PendingTrafficDetail>,
}

impl TrafficDetailTaskPool {
    pub(super) fn fill(&mut self, app: &mut TuiApp, initial_sequence: Option<u64>) {
        self.abort_stale(app);
        if let Some(sequence) = initial_sequence {
            self.start_sequence(app, sequence);
        }
        while self.has_capacity() {
            let Some(request) = app.begin_next_open_traffic_detail_load() else {
                break;
            };
            self.start_request(request);
        }
    }

    pub(super) async fn drain_finished(&mut self) -> Vec<TrafficDetailLoadResult> {
        let finished_sequences = self
            .pending
            .iter()
            .filter_map(|(sequence, pending)| pending.task.is_finished().then_some(*sequence))
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(finished_sequences.len());
        for sequence in finished_sequences {
            let pending = self
                .pending
                .remove(&sequence)
                .expect("finished pending detail task was just collected");
            results.push(pending.into_result().await);
        }
        results
    }

    pub(super) fn abort_all(self) {
        for pending in self.pending.into_values() {
            pending.abort();
        }
    }

    fn start_sequence(&mut self, app: &mut TuiApp, sequence: u64) {
        if self.pending.contains_key(&sequence) || !self.has_capacity() {
            return;
        }
        let Some(request) = app.begin_traffic_detail_load(sequence) else {
            return;
        };
        self.start_request(request);
    }

    fn start_request(&mut self, request: TrafficDetailLoadRequest) {
        if self.pending.contains_key(&request.sequence) || !self.has_capacity() {
            return;
        }
        self.pending.insert(
            request.sequence,
            PendingTrafficDetail {
                sequence: request.sequence,
                request_id: request.request_id,
                task: tokio::spawn(load_traffic_detail(request)),
            },
        );
    }

    fn abort_stale(&mut self, app: &TuiApp) {
        let stale_sequences = self
            .pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (!app.is_current_traffic_detail_request(*sequence, pending.request_id))
                    .then_some(*sequence)
            })
            .collect::<Vec<_>>();
        for sequence in stale_sequences {
            if let Some(pending) = self.pending.remove(&sequence) {
                pending.abort();
            }
        }
    }

    fn has_capacity(&self) -> bool {
        self.pending.len() < MAX_PENDING_TRAFFIC_DETAIL_LOADS
    }
}

struct PendingTrafficDetail {
    sequence: u64,
    request_id: u64,
    task: tokio::task::JoinHandle<TrafficDetailLoadResult>,
}

impl PendingTrafficDetail {
    async fn into_result(self) -> TrafficDetailLoadResult {
        match self.task.await {
            Ok(result) => result,
            Err(error) => TrafficDetailLoadResult::failed(
                self.sequence,
                self.request_id,
                format!("traffic detail task failed: {error}"),
            ),
        }
    }

    fn abort(self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::AgentConfig;

    use super::*;
    use crate::{process_catalog::ProcessCatalog, tui::runtime_attachment::RuntimeAttachment};

    #[tokio::test]
    async fn detail_task_pool_drains_all_finished_tasks_without_blocking_pending_tasks() {
        let mut pool = TrafficDetailTaskPool {
            pending: BTreeMap::from([
                (7, finished_pending(7, 11)),
                (8, finished_pending(8, 12)),
                (9, pending_forever(9, 13)),
            ]),
        };
        wait_for_finished(&pool, &[7, 8]).await;

        let mut results = pool.drain_finished().await;
        results.sort_by_key(|result| result.sequence);

        assert_eq!(
            results
                .iter()
                .map(|result| result.sequence)
                .collect::<Vec<_>>(),
            vec![7, 8]
        );
        assert!(!pool.pending.contains_key(&7));
        assert!(!pool.pending.contains_key(&8));
        assert!(pool.pending.contains_key(&9));
        pool.abort_all();
    }

    #[tokio::test]
    async fn detail_task_pool_keeps_pending_count_within_capacity() {
        let mut pool = TrafficDetailTaskPool {
            pending: BTreeMap::new(),
        };
        for sequence in 1..=MAX_PENDING_TRAFFIC_DETAIL_LOADS as u64 {
            pool.start_request(request(sequence));
        }

        pool.start_request(request(99));

        assert_eq!(pool.pending.len(), MAX_PENDING_TRAFFIC_DETAIL_LOADS);
        assert!(!pool.pending.contains_key(&99));
        pool.abort_all();
    }

    #[tokio::test]
    async fn detail_task_pool_evicts_stale_pending_tasks_before_refill() {
        let mut app = attached_app();
        let stale = app
            .begin_traffic_detail_load(41)
            .expect("attached app should create the initial detail request");
        let mut pool = TrafficDetailTaskPool {
            pending: BTreeMap::from([(
                stale.sequence,
                pending_forever(stale.sequence, stale.request_id),
            )]),
        };
        let replacement = app
            .begin_traffic_detail_load(41)
            .expect("same sequence should be able to supersede the request id");

        assert!(app.is_current_traffic_detail_request(41, replacement.request_id));

        pool.fill(&mut app, Some(42));

        assert!(!pool.pending.contains_key(&41));
        assert!(pool.pending.contains_key(&42));
        pool.abort_all();
    }

    fn request(sequence: u64) -> TrafficDetailLoadRequest {
        TrafficDetailLoadRequest {
            socket_path: PathBuf::from("/tmp/missing-admin.sock"),
            sequence,
            request_id: sequence + 1,
        }
    }

    fn attached_app() -> TuiApp {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        app.attach_agent(RuntimeAttachment::existing(PathBuf::from(
            "/tmp/missing-admin.sock",
        )));
        app
    }

    fn finished_pending(sequence: u64, request_id: u64) -> PendingTrafficDetail {
        PendingTrafficDetail {
            sequence,
            request_id,
            task: tokio::spawn(async move {
                TrafficDetailLoadResult::failed(sequence, request_id, "detail failed")
            }),
        }
    }

    fn pending_forever(sequence: u64, request_id: u64) -> PendingTrafficDetail {
        PendingTrafficDetail {
            sequence,
            request_id,
            task: tokio::spawn(async { std::future::pending::<TrafficDetailLoadResult>().await }),
        }
    }

    async fn wait_for_finished(pool: &TrafficDetailTaskPool, sequences: &[u64]) {
        for _ in 0..10 {
            if sequences.iter().all(|sequence| {
                pool.pending
                    .get(sequence)
                    .is_some_and(|pending| pending.task.is_finished())
            }) {
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}
