use crate::{
    BannerStatus, Config, Protocol, ResultV1, SCHEMA_VERSION, TargetState, config::ServiceConfig,
    permutation::Permutation, target,
};
use anyhow::{Context, bail};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LEASE_MS: i64 = 30_000;
const IDLE_SLEEP: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Running,
    Done,
    Failed,
}

impl TaskStatus {
    fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Running => "running",
            TaskStatus::Done => "done",
            TaskStatus::Failed => "failed",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "done" => Self::Done,
            "failed" => Self::Failed,
            _ => bail!("invalid task status {value}"),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskLease {
    pub scan_id: String,
    pub task_id: i64,
    pub round: u8,
    pub order_start: u64,
    pub order_end: u64,
    pub target_count: u64,
    pub seed_hex: String,
    pub config_toml: String,
    pub terminal_endpoint_indexes: Vec<u64>,
    pub lease_expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub status: String,
    pub target_count: u64,
    pub syn_attempts: u8,
    pub tasks_pending: u64,
    pub tasks_running: u64,
    pub tasks_done: u64,
    pub tasks_failed: u64,
    pub results_open: u64,
    pub results_closed: u64,
    pub results_unreachable: u64,
    pub observations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScanSummary {
    pub scan_id: String,
    pub target_count: u64,
    pub target_digest: String,
    pub task_count: u64,
    pub syn_attempts: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerOptions {
    pub coordinator: SocketAddr,
    pub work_dir: PathBuf,
    pub worker_id: Option<String>,
    pub exit_when_idle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello {
        worker_id: String,
        capabilities: Vec<String>,
    },
    Heartbeat {
        worker_id: String,
    },
    LeaseTask {
        worker_id: String,
    },
    RenewTask {
        worker_id: String,
        scan_id: String,
        task_id: i64,
    },
    SubmitObservations {
        worker_id: String,
        scan_id: String,
        task_id: i64,
        observations: Vec<ResultV1>,
    },
    CompleteTask {
        worker_id: String,
        scan_id: String,
        task_id: i64,
        summary: TaskRunSummary,
    },
    FailTask {
        worker_id: String,
        scan_id: String,
        task_id: i64,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok {
        rate_advice_mbps: Option<f64>,
    },
    Task {
        lease: Option<TaskLease>,
        rate_advice_mbps: Option<f64>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskRunSummary {
    pub materialized: u64,
    pub skipped_terminal: u64,
    pub sent: u64,
    pub open: u64,
    pub closed: u64,
    pub unreachable: u64,
    pub no_response: u64,
}

pub fn round_seed(base_seed: [u8; 32], round: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&base_seed);
    hasher.update(b"riftmap-distributed-round-v1");
    hasher.update(&[round]);
    *hasher.finalize().as_bytes()
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    fn memory() -> anyhow::Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory()?,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                config_toml TEXT NOT NULL,
                seed_hex TEXT NOT NULL,
                target_digest TEXT NOT NULL,
                target_count INTEGER NOT NULL,
                syn_attempts INTEGER NOT NULL,
                services_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                scan_id TEXT NOT NULL,
                task_id INTEGER NOT NULL,
                round INTEGER NOT NULL,
                order_start INTEGER NOT NULL,
                order_end INTEGER NOT NULL,
                status TEXT NOT NULL,
                lease_owner TEXT,
                lease_expires_at_ms INTEGER,
                attempt INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (scan_id, task_id),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_lease
                ON tasks(status, lease_expires_at_ms, scan_id, task_id);
            CREATE TABLE IF NOT EXISTS workers (
                worker_id TEXT PRIMARY KEY,
                last_heartbeat_ms INTEGER NOT NULL,
                capabilities_json TEXT NOT NULL,
                current_scan_id TEXT,
                current_task_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                task_id INTEGER NOT NULL,
                worker_id TEXT NOT NULL,
                endpoint_index INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS results (
                scan_id TEXT NOT NULL,
                endpoint_index INTEGER NOT NULL,
                result_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                syn_attempts INTEGER NOT NULL,
                rtt_ms REAL,
                conflicting_observations INTEGER NOT NULL,
                first_observed_at TEXT,
                last_observed_at TEXT,
                banner_status TEXT,
                result_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, endpoint_index, port, protocol)
            );
            ",
        )?;
        Ok(())
    }

    pub fn create_scan(
        &mut self,
        cfg: &Config,
        task_size: u64,
    ) -> anyhow::Result<CreateScanSummary> {
        anyhow::ensure!(task_size > 0, "task_size must be positive");
        let prepared = PreparedTargets::from_config(cfg)?;
        let mut seed = [0; 32];
        rand::rng().fill_bytes(&mut seed);
        let seed_hex = hex(&seed);
        let mut id_material = Vec::new();
        id_material.extend_from_slice(&seed);
        id_material.extend_from_slice(prepared.digest.as_bytes());
        let scan_id = hex(&blake3::hash(&id_material).as_bytes()[..12]);
        let config_toml = toml::to_string_pretty(&sanitized_config(cfg))?;
        let services_json = serde_json::to_string(&cfg.scan.services())?;
        let tx = self.conn.transaction()?;
        let now = now_ms();
        tx.execute(
            "INSERT INTO scans
             (scan_id, status, config_toml, seed_hex, target_digest, target_count, syn_attempts,
              services_json, created_at_ms, updated_at_ms)
             VALUES (?1, 'active', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                scan_id,
                config_toml,
                seed_hex,
                prepared.digest.as_str(),
                prepared.count as i64,
                cfg.scan.syn_attempts,
                services_json,
                now
            ],
        )?;
        let mut task_id = 0i64;
        for round in 0..cfg.scan.syn_attempts {
            let mut start = 0;
            while start < prepared.count {
                let end = start.saturating_add(task_size).min(prepared.count);
                tx.execute(
                    "INSERT INTO tasks
                     (scan_id, task_id, round, order_start, order_end, status, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                    params![scan_id, task_id, round, start as i64, end as i64, now],
                )?;
                task_id += 1;
                start = end;
            }
        }
        tx.commit()?;
        Ok(CreateScanSummary {
            scan_id,
            target_count: prepared.count,
            target_digest: prepared.digest,
            task_count: task_id as u64,
            syn_attempts: cfg.scan.syn_attempts,
        })
    }

    pub fn register_worker(&self, worker_id: &str, capabilities: &[String]) -> anyhow::Result<()> {
        let now = now_ms();
        self.conn.execute(
            "INSERT INTO workers
             (worker_id, last_heartbeat_ms, capabilities_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(worker_id) DO UPDATE SET
             last_heartbeat_ms=excluded.last_heartbeat_ms,
             capabilities_json=excluded.capabilities_json",
            params![worker_id, now, serde_json::to_string(capabilities)?],
        )?;
        Ok(())
    }

    pub fn heartbeat(&self, worker_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE workers SET last_heartbeat_ms=?2 WHERE worker_id=?1",
            params![worker_id, now_ms()],
        )?;
        Ok(())
    }

    pub fn lease_task(&mut self, worker_id: &str) -> anyhow::Result<Option<TaskLease>> {
        let tx = self.conn.transaction()?;
        let now = now_ms();
        let row = tx
            .query_row(
                "SELECT t.scan_id, t.task_id, t.round, t.order_start, t.order_end, s.target_count,
                        s.seed_hex, s.config_toml
                 FROM tasks t
                 JOIN scans s ON s.scan_id = t.scan_id
                 WHERE s.status = 'active'
                   AND (t.status = 'pending'
                        OR (t.status = 'running' AND t.lease_expires_at_ms < ?1))
                 ORDER BY t.round, t.task_id
                 LIMIT 1",
                params![now],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, u8>(2)?,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, i64>(5)? as u64,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            scan_id,
            task_id,
            round,
            order_start,
            order_end,
            target_count,
            seed_hex,
            config_toml,
        )) = row
        else {
            tx.execute(
                "UPDATE workers SET current_scan_id=NULL, current_task_id=NULL WHERE worker_id=?1",
                params![worker_id],
            )?;
            tx.commit()?;
            return Ok(None);
        };
        let expires = now + LEASE_MS;
        tx.execute(
            "UPDATE tasks
             SET status='running', lease_owner=?3, lease_expires_at_ms=?4,
                 attempt=attempt+1, updated_at_ms=?5
             WHERE scan_id=?1 AND task_id=?2",
            params![scan_id, task_id, worker_id, expires, now],
        )?;
        tx.execute(
            "UPDATE workers SET current_scan_id=?2, current_task_id=?3, last_heartbeat_ms=?4
             WHERE worker_id=?1",
            params![worker_id, scan_id, task_id, now],
        )?;
        let terminal_endpoint_indexes = terminal_endpoint_indexes_tx(
            &tx,
            &scan_id,
            target_count,
            &seed_hex,
            round,
            order_start,
            order_end,
        )?;
        tx.commit()?;
        Ok(Some(TaskLease {
            scan_id,
            task_id,
            round,
            order_start,
            order_end,
            target_count,
            seed_hex,
            config_toml,
            terminal_endpoint_indexes,
            lease_expires_at_ms: expires,
        }))
    }

    pub fn renew_task(&self, worker_id: &str, scan_id: &str, task_id: i64) -> anyhow::Result<()> {
        let changed = self.conn.execute(
            "UPDATE tasks
             SET lease_expires_at_ms=?4, updated_at_ms=?4
             WHERE scan_id=?1 AND task_id=?2 AND lease_owner=?3 AND status='running'",
            params![scan_id, task_id, worker_id, now_ms() + LEASE_MS],
        )?;
        anyhow::ensure!(changed == 1, "task lease is no longer owned by worker");
        Ok(())
    }

    pub fn submit_observations(
        &mut self,
        worker_id: &str,
        scan_id: &str,
        task_id: i64,
        observations: &[ResultV1],
    ) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        for result in observations {
            let endpoint_index = result_endpoint_index(&tx, scan_id, result)?
                .context("observation endpoint is outside scan targets")?;
            insert_observation(&tx, worker_id, task_id, endpoint_index, result)?;
            if result.state != TargetState::NoResponse {
                reduce_result(&tx, endpoint_index, result)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn complete_task(
        &mut self,
        worker_id: &str,
        scan_id: &str,
        task_id: i64,
    ) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE tasks
             SET status='done', lease_owner=NULL, lease_expires_at_ms=NULL, updated_at_ms=?4
             WHERE scan_id=?1 AND task_id=?2 AND lease_owner=?3",
            params![scan_id, task_id, worker_id, now_ms()],
        )?;
        anyhow::ensure!(changed == 1, "task lease is no longer owned by worker");
        tx.execute(
            "UPDATE workers SET current_scan_id=NULL, current_task_id=NULL WHERE worker_id=?1",
            params![worker_id],
        )?;
        mark_scan_completed_if_done(&tx, scan_id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn fail_task(
        &self,
        worker_id: &str,
        scan_id: &str,
        task_id: i64,
        error: &str,
    ) -> anyhow::Result<()> {
        let changed = self.conn.execute(
            "UPDATE tasks
             SET status='pending', lease_owner=NULL, lease_expires_at_ms=NULL,
                 last_error=?4, updated_at_ms=?5
             WHERE scan_id=?1 AND task_id=?2 AND lease_owner=?3",
            params![scan_id, task_id, worker_id, error, now_ms()],
        )?;
        anyhow::ensure!(changed == 1, "task lease is no longer owned by worker");
        Ok(())
    }

    pub fn status(&self, scan_id: &str) -> anyhow::Result<ScanStatus> {
        let (status, target_count, syn_attempts): (String, i64, u8) = self.conn.query_row(
            "SELECT status, target_count, syn_attempts FROM scans WHERE scan_id=?1",
            params![scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let mut task_counts = BTreeMap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT status, COUNT(*) FROM tasks WHERE scan_id=?1 GROUP BY status")?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        for row in rows {
            let (state, count) = row?;
            task_counts.insert(TaskStatus::parse(&state)?.as_str().to_owned(), count);
        }
        let results_open = self.result_count(scan_id, TargetState::Open)?;
        let results_closed = self.result_count(scan_id, TargetState::Closed)?;
        let results_unreachable = self.result_count(scan_id, TargetState::Unreachable)?;
        let observations = self.conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE scan_id=?1",
            params![scan_id],
            |row| row.get::<_, i64>(0),
        )? as u64;
        Ok(ScanStatus {
            scan_id: scan_id.to_owned(),
            status,
            target_count: target_count as u64,
            syn_attempts,
            tasks_pending: *task_counts.get("pending").unwrap_or(&0),
            tasks_running: *task_counts.get("running").unwrap_or(&0),
            tasks_done: *task_counts.get("done").unwrap_or(&0),
            tasks_failed: *task_counts.get("failed").unwrap_or(&0),
            results_open,
            results_closed,
            results_unreachable,
            observations,
        })
    }

    fn result_count(&self, scan_id: &str, state: TargetState) -> anyhow::Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM results WHERE scan_id=?1 AND state=?2",
            params![scan_id, serde_plain(state)?],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn export(&self, scan_id: &str, output: impl AsRef<Path>) -> anyhow::Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT result_json FROM results
             WHERE scan_id=?1
             ORDER BY ip, port, protocol",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;
        let mut out = fs::File::create(output)?;
        let mut count = 0;
        for row in rows {
            out.write_all(row?.as_bytes())?;
            out.write_all(b"\n")?;
            count += 1;
        }
        Ok(count)
    }

    pub fn report(&self, scan_id: &str) -> anyhow::Result<serde_json::Value> {
        let status = self.status(scan_id)?;
        let mut protocol_counts = BTreeMap::<String, u64>::new();
        let mut banner_status_counts = BTreeMap::<String, u64>::new();
        let mut stmt = self
            .conn
            .prepare("SELECT protocol, banner_status FROM results WHERE scan_id=?1")?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        for row in rows {
            let (protocol, banner_status) = row?;
            *protocol_counts.entry(protocol).or_default() += 1;
            if let Some(status) = banner_status {
                *banner_status_counts.entry(status).or_default() += 1;
            }
        }
        Ok(serde_json::json!({
            "status": status,
            "protocol_counts": protocol_counts,
            "banner_status_counts": banner_status_counts,
        }))
    }
}

fn terminal_endpoint_indexes_tx(
    tx: &Transaction<'_>,
    scan_id: &str,
    target_count: u64,
    seed_hex: &str,
    round: u8,
    order_start: u64,
    order_end: u64,
) -> anyhow::Result<Vec<u64>> {
    let seed = crate::job::decode_seed(seed_hex)?;
    let perm = Permutation::new(target_count, round_seed(seed, round))?;
    let mut terminal = Vec::new();
    let mut stmt = tx.prepare(
        "SELECT 1 FROM results
         WHERE scan_id=?1 AND endpoint_index=?2
           AND state IN ('open', 'closed', 'unreachable')
         LIMIT 1",
    )?;
    for order in order_start..order_end {
        let index = perm.get(order);
        let exists = stmt
            .query_row(params![scan_id, index as i64], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            terminal.push(index);
        }
    }
    Ok(terminal)
}

fn result_endpoint_index(
    tx: &Transaction<'_>,
    scan_id: &str,
    result: &ResultV1,
) -> anyhow::Result<Option<u64>> {
    let (config_toml,): (String,) = tx.query_row(
        "SELECT config_toml FROM scans WHERE scan_id=?1",
        params![scan_id],
        |row| Ok((row.get(0)?,)),
    )?;
    let cfg: Config = toml::from_str(&config_toml)?;
    let prepared = PreparedTargets::from_config(&cfg)?;
    Ok(prepared.endpoint_index(result.ip, result.port, result.protocol))
}

fn insert_observation(
    tx: &Transaction<'_>,
    worker_id: &str,
    task_id: i64,
    endpoint_index: u64,
    result: &ResultV1,
) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO observations
         (scan_id, task_id, worker_id, endpoint_index, port, protocol, observed_at_ms, result_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            result.scan_id,
            task_id,
            worker_id,
            endpoint_index as i64,
            result.port,
            serde_plain(result.protocol)?,
            now_ms(),
            serde_json::to_string(result)?
        ],
    )?;
    Ok(())
}

fn reduce_result(
    tx: &Transaction<'_>,
    endpoint_index: u64,
    incoming: &ResultV1,
) -> anyhow::Result<()> {
    let existing = tx
        .query_row(
            "SELECT result_json FROM results
             WHERE scan_id=?1 AND endpoint_index=?2 AND port=?3 AND protocol=?4",
            params![
                incoming.scan_id,
                endpoint_index as i64,
                incoming.port,
                serde_plain(incoming.protocol)?
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let mut chosen = incoming.clone();
    if let Some(existing) = existing {
        let current: ResultV1 = serde_json::from_str(&existing)?;
        chosen = merge_result(current, incoming.clone());
    }
    tx.execute(
        "INSERT INTO results
         (scan_id, endpoint_index, result_id, ip, port, protocol, state, syn_attempts, rtt_ms,
          conflicting_observations, first_observed_at, last_observed_at, banner_status, result_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(scan_id, endpoint_index, port, protocol) DO UPDATE SET
          result_id=excluded.result_id,
          ip=excluded.ip,
          state=excluded.state,
          syn_attempts=excluded.syn_attempts,
          rtt_ms=excluded.rtt_ms,
          conflicting_observations=excluded.conflicting_observations,
          first_observed_at=excluded.first_observed_at,
          last_observed_at=excluded.last_observed_at,
          banner_status=excluded.banner_status,
          result_json=excluded.result_json",
        params![
            chosen.scan_id,
            endpoint_index as i64,
            chosen.result_id,
            chosen.ip.to_string(),
            chosen.port,
            serde_plain(chosen.protocol)?,
            serde_plain(chosen.state)?,
            chosen.syn_attempts,
            chosen.rtt_ms,
            chosen.conflicting_observations,
            chosen.first_observed_at,
            chosen.last_observed_at,
            chosen.banner_status.map(serde_plain).transpose()?,
            serde_json::to_string(&chosen)?,
        ],
    )?;
    Ok(())
}

fn merge_result(current: ResultV1, incoming: ResultV1) -> ResultV1 {
    let conflict =
        current.state != incoming.state || current.banner_status != incoming.banner_status;
    let mut chosen = if incoming.state.rank() > current.state.rank() {
        incoming
    } else if incoming.state.rank() < current.state.rank() {
        current
    } else if incoming.banner_status == Some(BannerStatus::Ok)
        && current.banner_status != Some(BannerStatus::Ok)
    {
        incoming
    } else {
        current
    };
    if conflict {
        chosen.conflicting_observations = chosen.conflicting_observations.saturating_add(1);
    }
    chosen
}

fn mark_scan_completed_if_done(tx: &Transaction<'_>, scan_id: &str) -> anyhow::Result<()> {
    let remaining: i64 = tx.query_row(
        "SELECT COUNT(*) FROM tasks WHERE scan_id=?1 AND status != 'done'",
        params![scan_id],
        |row| row.get(0),
    )?;
    if remaining == 0 {
        tx.execute(
            "UPDATE scans SET status='completed', updated_at_ms=?2 WHERE scan_id=?1",
            params![scan_id, now_ms()],
        )?;
    }
    Ok(())
}

pub fn serve(state: impl AsRef<Path>, listen: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)?;
    eprintln!("coordinator_listen: {}", listener.local_addr()?);
    for stream in listener.incoming() {
        let stream = stream?;
        let state = state.as_ref().to_owned();
        thread::spawn(move || {
            if let Err(error) = handle_client(&state, stream) {
                tracing::warn!(%error, "distributed client failed");
            }
        });
    }
    Ok(())
}

fn handle_client(state: &Path, stream: TcpStream) -> anyhow::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for line in reader.lines() {
        let line = line?;
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => dispatch_request(state, request),
            Err(error) => Ok(Response::Error {
                message: error.to_string(),
            }),
        };
        serde_json::to_writer(&mut writer, &response?)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn dispatch_request(state: &Path, request: Request) -> anyhow::Result<Response> {
    let mut store = Store::open(state)?;
    match request {
        Request::Hello {
            worker_id,
            capabilities,
        } => {
            store.register_worker(&worker_id, &capabilities)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
        Request::Heartbeat { worker_id } => {
            store.heartbeat(&worker_id)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
        Request::LeaseTask { worker_id } => Ok(Response::Task {
            lease: store.lease_task(&worker_id)?,
            rate_advice_mbps: None,
        }),
        Request::RenewTask {
            worker_id,
            scan_id,
            task_id,
        } => {
            store.renew_task(&worker_id, &scan_id, task_id)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
        Request::SubmitObservations {
            worker_id,
            scan_id,
            task_id,
            observations,
        } => {
            store.submit_observations(&worker_id, &scan_id, task_id, &observations)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
        Request::CompleteTask {
            worker_id,
            scan_id,
            task_id,
            summary: _,
        } => {
            store.complete_task(&worker_id, &scan_id, task_id)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
        Request::FailTask {
            worker_id,
            scan_id,
            task_id,
            error,
        } => {
            store.fail_task(&worker_id, &scan_id, task_id, &error)?;
            Ok(Response::Ok {
                rate_advice_mbps: None,
            })
        }
    }
}

pub fn run_worker(options: WorkerOptions) -> anyhow::Result<()> {
    fs::create_dir_all(&options.work_dir)?;
    let worker_id = options.worker_id.unwrap_or_else(random_worker_id);
    send_request(
        options.coordinator,
        Request::Hello {
            worker_id: worker_id.clone(),
            capabilities: vec!["simulation".into()],
        },
    )?;
    loop {
        let response = send_request(
            options.coordinator,
            Request::LeaseTask {
                worker_id: worker_id.clone(),
            },
        )?;
        let lease = match response {
            Response::Task {
                lease: Some(lease), ..
            } => lease,
            Response::Task { lease: None, .. } if options.exit_when_idle => return Ok(()),
            Response::Task { lease: None, .. } => {
                thread::sleep(IDLE_SLEEP);
                continue;
            }
            Response::Error { message } => bail!(message),
            Response::Ok { .. } => bail!("unexpected coordinator response"),
        };
        let (stop_renew, renew_stop_rx) = mpsc::channel();
        let renewer = spawn_renewer(
            options.coordinator,
            worker_id.clone(),
            lease.scan_id.clone(),
            lease.task_id,
            renew_stop_rx,
        );
        let result = run_task(&lease);
        let _ = stop_renew.send(());
        let _ = renewer.join();
        match result {
            Ok((summary, observations)) => {
                send_request(
                    options.coordinator,
                    Request::SubmitObservations {
                        worker_id: worker_id.clone(),
                        scan_id: lease.scan_id.clone(),
                        task_id: lease.task_id,
                        observations,
                    },
                )?;
                send_request(
                    options.coordinator,
                    Request::CompleteTask {
                        worker_id: worker_id.clone(),
                        scan_id: lease.scan_id,
                        task_id: lease.task_id,
                        summary,
                    },
                )?;
            }
            Err(error) => {
                send_request(
                    options.coordinator,
                    Request::FailTask {
                        worker_id: worker_id.clone(),
                        scan_id: lease.scan_id,
                        task_id: lease.task_id,
                        error: error.to_string(),
                    },
                )?;
            }
        }
    }
}

fn spawn_renewer(
    coordinator: SocketAddr,
    worker_id: String,
    scan_id: String,
    task_id: i64,
    stop: mpsc::Receiver<()>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while stop.recv_timeout(Duration::from_secs(10)).is_err() {
            let _ = send_request(
                coordinator,
                Request::RenewTask {
                    worker_id: worker_id.clone(),
                    scan_id: scan_id.clone(),
                    task_id,
                },
            );
        }
    })
}

fn send_request(addr: SocketAddr, request: Request) -> anyhow::Result<Response> {
    let mut stream = TcpStream::connect(addr)?;
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let response: Response = serde_json::from_str(&line)?;
    if let Response::Error { message } = &response {
        bail!(message.clone());
    }
    Ok(response)
}

fn run_task(lease: &TaskLease) -> anyhow::Result<(TaskRunSummary, Vec<ResultV1>)> {
    let cfg: Config = toml::from_str(&lease.config_toml)?;
    anyhow::ensure!(
        cfg.simulation.enabled,
        "distributed live scanning is not implemented yet; enable [simulation] for worker execution"
    );
    let prepared = PreparedTargets::from_config(&cfg)?;
    let seed = crate::job::decode_seed(&lease.seed_hex)?;
    let perm = Permutation::new(lease.target_count, round_seed(seed, lease.round))?;
    let terminal: BTreeSet<u64> = lease.terminal_endpoint_indexes.iter().copied().collect();
    let mut observations = Vec::new();
    let mut summary = TaskRunSummary::default();
    for order in lease.order_start..lease.order_end {
        let endpoint_index = perm.get(order);
        summary.materialized += 1;
        if terminal.contains(&endpoint_index) {
            summary.skipped_terminal += 1;
            continue;
        }
        let Some(endpoint) = prepared.endpoint_at(endpoint_index) else {
            bail!("endpoint index {endpoint_index} is out of range");
        };
        summary.sent += 1;
        let result = simulated_result(
            &cfg,
            &lease.scan_id,
            lease.round + 1,
            endpoint_index,
            endpoint,
        )?;
        match result.state {
            TargetState::Open => summary.open += 1,
            TargetState::Closed => summary.closed += 1,
            TargetState::Unreachable => summary.unreachable += 1,
            TargetState::NoResponse => summary.no_response += 1,
        }
        observations.push(result);
    }
    Ok((summary, observations))
}

#[derive(Clone)]
struct PreparedTargets {
    ranges: Vec<target::Ipv4Range>,
    services: Vec<ServiceConfig>,
    count: u64,
    digest: String,
}

impl PreparedTargets {
    fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let includes = target::parse_files(&cfg.targets.include)?;
        let excludes = target::parse_files(&cfg.targets.exclude)?;
        let ranges = target::filter_allowed(
            &target::subtract(&includes, &excludes),
            cfg.targets.allow_private,
        );
        let services = cfg.scan.services();
        let host_count = target::count(&ranges);
        let count = host_count.saturating_mul(services.len() as u64);
        anyhow::ensure!(
            count > 0,
            "target set is empty after exclusions and safety policy"
        );
        anyhow::ensure!(
            count <= cfg.targets.max_targets,
            "target count {count} exceeds max_targets {}",
            cfg.targets.max_targets
        );
        let mut hasher = blake3::Hasher::new();
        for ip in target::iter(&ranges) {
            for service in &services {
                hasher.update(&ip.octets());
                hasher.update(&service.port.to_be_bytes());
                hasher.update(&[crate::job::protocol_code(service.protocol)]);
            }
        }
        Ok(Self {
            ranges,
            services,
            count,
            digest: hasher.finalize().to_hex().to_string(),
        })
    }

    fn endpoint_at(&self, endpoint_index: u64) -> Option<Endpoint> {
        let service_count = self.services.len() as u64;
        if service_count == 0 || endpoint_index >= self.count {
            return None;
        }
        let host_index = endpoint_index / service_count;
        let service = self.services[(endpoint_index % service_count) as usize];
        let ip = nth_ip(&self.ranges, host_index)?;
        Some(Endpoint { ip, service })
    }

    fn endpoint_index(&self, ip: Ipv4Addr, port: u16, protocol: Protocol) -> Option<u64> {
        let host_index = ip_index(&self.ranges, ip)?;
        self.services
            .iter()
            .position(|service| service.port == port && service.protocol == protocol)
            .map(|service_index| host_index * self.services.len() as u64 + service_index as u64)
    }
}

#[derive(Clone, Copy)]
struct Endpoint {
    ip: Ipv4Addr,
    service: ServiceConfig,
}

fn nth_ip(ranges: &[target::Ipv4Range], mut index: u64) -> Option<Ipv4Addr> {
    for range in ranges {
        let len = range.len();
        if index < len {
            return Some(Ipv4Addr::from(range.start + index as u32));
        }
        index -= len;
    }
    None
}

fn ip_index(ranges: &[target::Ipv4Range], ip: Ipv4Addr) -> Option<u64> {
    let value = u32::from(ip);
    let mut base = 0u64;
    for range in ranges {
        if range.start <= value && value <= range.end {
            return Some(base + u64::from(value - range.start));
        }
        base += range.len();
    }
    None
}

fn simulated_result(
    cfg: &Config,
    scan_id: &str,
    attempts: u8,
    _endpoint_index: u64,
    endpoint: Endpoint,
) -> anyhow::Result<ResultV1> {
    let state = simulated_state(cfg, scan_id, endpoint);
    let rtt_ms =
        (state != TargetState::NoResponse).then(|| simulated_rtt_ms(cfg, scan_id, endpoint));
    let observed = now_ms().to_string();
    let mut result = ResultV1 {
        schema_version: SCHEMA_VERSION,
        result_id: crate::result::result_id(
            scan_id,
            endpoint.ip,
            endpoint.service.port,
            endpoint.service.protocol,
        ),
        scan_id: scan_id.to_owned(),
        ip: endpoint.ip,
        port: endpoint.service.port,
        protocol: endpoint.service.protocol,
        state,
        syn_attempts: attempts,
        rtt_ms,
        conflicting_observations: 0,
        first_observed_at: (state != TargetState::NoResponse).then(|| observed.clone()),
        last_observed_at: (state != TargetState::NoResponse).then_some(observed),
        banner_status: None,
        banner_base64: None,
        banner_text: None,
        ssh: None,
        ftp: None,
        mysql: None,
        smtp: None,
        redis: None,
        postgres: None,
    };
    if state == TargetState::Open && cfg.simulation.banner {
        let raw = simulated_banner(endpoint.service.protocol);
        let parsed = crate::protocol::parse(endpoint.service.protocol, &raw).map_err(|status| {
            anyhow::anyhow!(
                "parse simulated {:?} banner failed with {:?}",
                endpoint.service.protocol,
                status
            )
        })?;
        result.banner_status = Some(BannerStatus::Ok);
        result.banner_base64 = Some(base64_encode(&raw));
        result.banner_text = parsed.text;
        result.ssh = parsed.ssh;
        result.ftp = parsed.ftp;
        result.mysql = parsed.mysql;
        result.smtp = parsed.smtp;
        result.redis = parsed.redis;
        result.postgres = parsed.postgres;
    }
    Ok(result)
}

fn simulated_state(cfg: &Config, scan_id: &str, endpoint: Endpoint) -> TargetState {
    let sample = hash_unit(cfg, scan_id, endpoint, b"state");
    let open = cfg.simulation.open_ratio;
    let closed = open + cfg.simulation.closed_ratio;
    let unreachable = closed + cfg.simulation.unreachable_ratio;
    if sample < open {
        TargetState::Open
    } else if sample < closed {
        TargetState::Closed
    } else if sample < unreachable {
        TargetState::Unreachable
    } else {
        TargetState::NoResponse
    }
}

fn simulated_rtt_ms(cfg: &Config, scan_id: &str, endpoint: Endpoint) -> f64 {
    let sample = hash_unit(cfg, scan_id, endpoint, b"rtt");
    cfg.simulation.rtt_min_ms + (cfg.simulation.rtt_max_ms - cfg.simulation.rtt_min_ms) * sample
}

fn hash_unit(cfg: &Config, scan_id: &str, endpoint: Endpoint, domain: &[u8]) -> f64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(cfg.simulation.seed.as_bytes());
    hasher.update(scan_id.as_bytes());
    hasher.update(domain);
    hasher.update(&endpoint.ip.octets());
    hasher.update(&endpoint.service.port.to_be_bytes());
    hasher.update(&[crate::job::protocol_code(endpoint.service.protocol)]);
    let hash = hasher.finalize();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_be_bytes(bytes) as f64 / (u64::MAX as f64 + 1.0)
}

fn simulated_banner(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::Ssh => b"SSH-2.0-RiftMapSim_1.0\r\n".to_vec(),
        Protocol::Ftp => b"220 riftmap-sim FTP ready\r\n".to_vec(),
        Protocol::Mysql => mysql_banner(),
        Protocol::Smtp => b"220 riftmap-sim ESMTP ready\r\n".to_vec(),
        Protocol::Redis => b"+PONG\r\n".to_vec(),
        Protocol::Postgres => postgres_banner(),
    }
}

fn mysql_banner() -> Vec<u8> {
    let mut payload = vec![10];
    payload.extend_from_slice(b"8.0.36-riftmap-sim\0");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&0x1234u16.to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&0x5678u16.to_le_bytes());
    let len = payload.len();
    let mut packet = vec![(len & 0xff) as u8, ((len >> 8) & 0xff) as u8, 0, 0];
    packet.extend_from_slice(&payload);
    packet
}

fn postgres_banner() -> Vec<u8> {
    let payload = b"SERROR\0Msimulated startup response\0\0";
    let len = (payload.len() + 4) as u32;
    let mut packet = vec![b'E'];
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn sanitized_config(cfg: &Config) -> Config {
    cfg.clone()
}

fn random_worker_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    format!("worker-{}", hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
            out
        })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn serde_plain<T: Serialize>(value: T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&value)?.trim_matches('"').to_owned())
}

fn base64_encode(raw: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BudgetConfig, NetworkConfig, OutputConfig, ScanConfig, SimulationConfig, SourceIp,
        TargetsConfig,
    };

    fn config(root: &Path, include: PathBuf) -> Config {
        Config {
            scan: ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![],
                syn_attempts: 3,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 8,
                banner_connects_per_second: 10,
                banner_queue_capacity: 128,
                max_runtime_secs: None,
                ssh: Default::default(),
            },
            budget: BudgetConfig::default(),
            targets: TargetsConfig {
                include: vec![include],
                exclude: vec![],
                allow_private: true,
                max_targets: 100,
            },
            network: NetworkConfig {
                interface: "lo".into(),
                source_ip: SourceIp("127.0.0.1".into()),
                provider_egress_mbps: 100.0,
                application_ratio: 0.8,
                dynamic_application_mbps_file: None,
                tc_ratio: 0.85,
                require_tc: false,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: root.join("jobs"),
                output_all: true,
            },
            simulation: SimulationConfig {
                enabled: true,
                open_ratio: 1.0,
                closed_ratio: 0.0,
                unreachable_ratio: 0.0,
                seed: "test".into(),
                rtt_min_ms: 1.0,
                rtt_max_ms: 2.0,
                banner: true,
            },
        }
    }

    #[test]
    fn round_seed_changes_per_round_and_permutation_is_bijective() -> anyhow::Result<()> {
        let base = [7; 32];
        assert_eq!(round_seed(base, 0), round_seed(base, 0));
        assert_ne!(round_seed(base, 0), round_seed(base, 1));
        let first = Permutation::new(64, round_seed(base, 0))?;
        let second = Permutation::new(64, round_seed(base, 1))?;
        let first_values: BTreeSet<_> = (0..64).map(|i| first.get(i)).collect();
        let second_values: BTreeSet<_> = (0..64).map(|i| second.get(i)).collect();
        assert_eq!(first_values.len(), 64);
        assert_eq!(second_values.len(), 64);
        assert_ne!(
            (0..64).map(|i| first.get(i)).collect::<Vec<_>>(),
            (0..64).map(|i| second.get(i)).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn store_leases_renews_expires_and_reassigns() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = config(temp.path(), include);
        let mut store = Store::memory()?;
        store.create_scan(&cfg, 1)?;
        store.register_worker("one", &[])?;
        store.register_worker("two", &[])?;

        let lease = store.lease_task("one")?.context("lease")?;
        store.renew_task("one", &lease.scan_id, lease.task_id)?;
        let error = store
            .renew_task("two", &lease.scan_id, lease.task_id)
            .unwrap_err();
        assert!(error.to_string().contains("no longer owned"));
        store.conn.execute(
            "UPDATE tasks SET lease_expires_at_ms=?3 WHERE scan_id=?1 AND task_id=?2",
            params![lease.scan_id, lease.task_id, now_ms() - 1],
        )?;
        let reassigned = store.lease_task("two")?.context("reassigned")?;
        assert_eq!(reassigned.task_id, lease.task_id);
        Ok(())
    }

    #[test]
    fn complete_and_fail_require_current_lease_owner() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include);
        let mut store = Store::memory()?;
        let scan = store.create_scan(&cfg, 1)?;
        let lease = store.lease_task("owner")?.context("lease")?;

        let error = store
            .complete_task("other", &scan.scan_id, lease.task_id)
            .unwrap_err();
        assert!(error.to_string().contains("no longer owned"));

        let error = store
            .fail_task("other", &scan.scan_id, lease.task_id, "failed")
            .unwrap_err();
        assert!(error.to_string().contains("no longer owned"));

        store.complete_task("owner", &scan.scan_id, lease.task_id)?;
        assert_eq!(store.status(&scan.scan_id)?.tasks_done, 1);
        Ok(())
    }

    #[test]
    fn reducer_is_idempotent_and_tracks_conflicts() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include);
        let mut store = Store::memory()?;
        let scan = store.create_scan(&cfg, 10)?;
        let mut lease = store.lease_task("worker")?.context("lease")?;
        lease.scan_id = scan.scan_id.clone();
        let (_, observations) = run_task(&lease)?;
        store.submit_observations("worker", &scan.scan_id, lease.task_id, &observations)?;
        store.submit_observations("worker", &scan.scan_id, lease.task_id, &observations)?;
        assert_eq!(store.status(&scan.scan_id)?.results_open, 1);

        let mut closed = observations[0].clone();
        closed.state = TargetState::Closed;
        store.submit_observations("worker", &scan.scan_id, lease.task_id, &[closed])?;
        let json: String = store.conn.query_row(
            "SELECT result_json FROM results WHERE scan_id=?1",
            params![scan.scan_id],
            |row| row.get(0),
        )?;
        let result: ResultV1 = serde_json::from_str(&json)?;
        assert_eq!(result.state, TargetState::Open);
        assert!(result.conflicting_observations > 0);
        Ok(())
    }

    #[test]
    fn terminal_results_are_skipped_in_later_rounds() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = config(temp.path(), include);
        let mut store = Store::memory()?;
        let scan = store.create_scan(&cfg, 2)?;
        let first = store.lease_task("worker")?.context("first")?;
        let (_, observations) = run_task(&first)?;
        store.submit_observations("worker", &scan.scan_id, first.task_id, &observations)?;
        store.complete_task("worker", &scan.scan_id, first.task_id)?;

        let second = store.lease_task("worker")?.context("second")?;
        assert_eq!(second.round, 1);
        assert!(!second.terminal_endpoint_indexes.is_empty());
        let (summary, _) = run_task(&second)?;
        assert!(summary.skipped_terminal > 0);
        Ok(())
    }
}
