//! The encino session daemon.
//!
//! Started by `encino unlock`, which hands it the master key on stdin. Serves
//! that key to same-user clients until it expires or is told to stop.
//!
//! On the way out it re-encrypts anything still decrypted, because it is the
//! only process that outlives the command which decrypted a document and still
//! holds the key needed to put it back.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
use crate::protocol::pipe_name;
use crate::protocol::{Request, Response};
use anyhow::{Context, Result, bail};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use crate::listener;
#[cfg(windows)]
use crate::pipe;

/// Keeps the key out of swap; same idea on both platforms, different call.
#[cfg(unix)]
use crate::unix::LockedPages;
#[cfg(windows)]
use crate::win::LockedPages;

/// Key material for the session, locked into physical memory so it cannot reach
/// the page file, and zeroized on drop.
struct HeldKey {
    bytes: Vec<u8>,
    /// `VirtualLock` or `mlock`. Either may decline (constrained working set,
    /// low `RLIMIT_MEMLOCK`); not fatal, since the key is zeroized on drop.
    #[cfg(any(windows, unix))]
    _locked: Option<LockedPages>,
}

impl HeldKey {
    fn new(mut bytes: Vec<u8>) -> Self {
        #[cfg(any(windows, unix))]
        let locked = LockedPages::lock(&mut bytes);

        HeldKey {
            bytes,
            #[cfg(any(windows, unix))]
            _locked: locked,
        }
    }

    fn encoded(&self) -> Zeroizing<String> {
        use base64::Engine;
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&self.bytes))
    }
}

impl Drop for HeldKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct Agent {
    key: Mutex<Option<HeldKey>>,
    vault_root: PathBuf,
    deadline: Mutex<Instant>,
    stopping: AtomicBool,
}

impl Agent {
    fn remaining(&self) -> Duration {
        self.deadline.lock().map(|d| d.saturating_duration_since(Instant::now())).unwrap_or_default()
    }

    fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    fn handle(&self, request: Request) -> Response {
        if self.expired() {
            return Response::Error { message: "the session has expired".into() };
        }

        match request {
            Request::MasterKey => match self.key.lock().ok().and_then(|k| k.as_ref().map(|k| k.encoded())) {
                Some(key) => {
                    Response::MasterKey { key: key.to_string(), expires_in: self.remaining().as_secs() }
                }
                None => Response::Error { message: "the session has ended".into() },
            },
            Request::Status => Response::Status {
                vault: self.vault_root.display().to_string(),
                expires_in: self.remaining().as_secs(),
            },
            Request::SetTimeout { seconds } => {
                let capped = seconds.min(12 * 3600);
                if let Ok(mut deadline) = self.deadline.lock() {
                    *deadline = Instant::now() + Duration::from_secs(capped);
                }
                Response::Done
            }
            Request::Lock => {
                // The client re-encrypts before asking to lock, so anything left
                // open is a document it could not close. Retry rather than drop
                // the key and strand the plaintext.
                self.close_open_documents();
                self.forget();
                self.stopping.store(true, Ordering::SeqCst);
                Response::Done
            }
        }
    }

    /// Re-encrypt anything still decrypted, while the key is still available.
    fn close_open_documents(&self) {
        let key_bytes = match self.key.lock() {
            Ok(held) => match held.as_ref() {
                Some(held) => held.bytes.clone(),
                None => return,
            },
            Err(_) => return,
        };
        let key_bytes = Zeroizing::new(key_bytes);

        let Ok(master) = encino_core::crypto::Key::from_slice(&key_bytes) else {
            return;
        };
        // An ordinary command may hold the vault lock when the timer fires.
        // Giving up would end the session with documents still decrypted, so
        // wait for it.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut session = loop {
            let Ok(vault) = encino_core::Vault::open(&self.vault_root) else {
                return;
            };
            match encino_core::Session::from_master(vault, &master) {
                Ok(session) => break session,
                Err(encino_core::Error::VaultInUse { .. }) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(_) => return,
            }
        };

        let open: Vec<_> = session.open_documents().iter().map(|e| e.path.clone()).collect();
        for name in open {
            // Best effort: one stuck document must not stop the rest.
            let _ = session.checkin(&name);
        }
    }

    fn forget(&self) {
        if let Ok(mut held) = self.key.lock() {
            held.take();
        }
    }
}

pub fn serve(vault: PathBuf, vault_id: &str, timeout: Duration) -> Result<()> {
    // Does nothing unless ENCINO_AGENT_DEBUG is set.
    crate::diag::install_panic_hook();

    if vault_id.is_empty() {
        bail!("a vault id is required to serve a session");
    }

    // The key arrives on stdin; a command line is readable by process listings.
    let key = read_key_from_stdin().context("could not read the master key")?;

    run(vault, vault_id, key, timeout)
}

fn read_key_from_stdin() -> Result<Vec<u8>> {
    use base64::Engine;

    let mut encoded = String::new();
    std::io::stdin().read_to_string(&mut encoded)?;
    let encoded = Zeroizing::new(encoded);

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("the key was not valid base64")?;
    if bytes.len() != 32 {
        bail!("the key was {} bytes, expected 32", bytes.len());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn run(vault: PathBuf, vault_id: &str, key: Vec<u8>, timeout: Duration) -> Result<()> {
    let sid = crate::win::current_user_sid().context("could not determine the current user")?;
    let name = pipe_name(vault_id, &sid);

    let agent = Arc::new(Agent {
        key: Mutex::new(Some(HeldKey::new(key))),
        vault_root: vault,
        deadline: Mutex::new(Instant::now() + timeout),
        stopping: AtomicBool::new(false),
    });

    // A watchdog rather than a per-accept timeout: the server blocks in accept,
    // and a session must end on time whether or not anyone connects again.
    {
        let agent = Arc::clone(&agent);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(500));
                if agent.stopping.load(Ordering::SeqCst) {
                    return;
                }
                if agent.expired() {
                    break;
                }
            }
            agent.close_open_documents();
            agent.forget();
            std::process::exit(0);
        });
    }

    let mut server = pipe::PipeServer::create(&name, &sid).inspect_err(|e| {
        crate::diag::record(&format!("could not create the session pipe: {e}"));
    })?;
    crate::diag::record(&format!("serving {name} for {}s", timeout.as_secs()));

    // A client giving up before being accepted must not end the session, but a
    // dead pipe must not become a silent hot loop either.
    const CONSECUTIVE_FAILURES_BEFORE_GIVING_UP: u32 = 50;
    let mut failures: u32 = 0;

    while !agent.stopping.load(Ordering::SeqCst) && !agent.expired() {
        match server.accept() {
            Ok(connection) => {
                failures = 0;
                serve_one(&agent, connection);
            }
            Err(e) => {
                failures += 1;
                if failures >= CONSECUTIVE_FAILURES_BEFORE_GIVING_UP {
                    crate::diag::record(&format!(
                        "giving up after {failures} consecutive accept failures; last was: {e}"
                    ));
                    break;
                }
                if failures == 1 {
                    crate::diag::record(&format!("accept failed: {e}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    crate::diag::record(&format!(
        "accept loop ended: stopping={} expired={} remaining={}s",
        agent.stopping.load(Ordering::SeqCst),
        agent.expired(),
        agent.remaining().as_secs()
    ));

    // Re-encrypt before the key goes away, even on the failure path.
    agent.close_open_documents();
    agent.forget();
    Ok(())
}

#[cfg(windows)]
fn serve_one(agent: &Agent, connection: pipe::PipeConnection) {
    let mut reader = BufReader::new(&connection);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }

    let response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(request) => agent.handle(request),
        Err(e) => Response::Error { message: format!("malformed request: {e}") },
    };
    line.zeroize();

    if let Ok(mut encoded) = serde_json::to_string(&response) {
        let mut writer = &connection;
        let _ = writer.write_all(encoded.as_bytes());
        let _ = writer.write_all(b"\n");
        let _ = writer.flush();
        encoded.zeroize();
    }
}

#[cfg(unix)]
fn run(vault: PathBuf, vault_id: &str, key: Vec<u8>, timeout: Duration) -> Result<()> {
    let path = crate::protocol::socket_path(vault_id);

    let agent = Arc::new(Agent {
        key: Mutex::new(Some(HeldKey::new(key))),
        vault_root: vault,
        deadline: Mutex::new(Instant::now() + timeout),
        stopping: AtomicBool::new(false),
    });

    // Same watchdog as on Windows.
    {
        let agent = Arc::clone(&agent);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(500));
                if agent.stopping.load(Ordering::SeqCst) {
                    return;
                }
                if agent.expired() {
                    break;
                }
            }
            agent.close_open_documents();
            agent.forget();
            std::process::exit(0);
        });
    }

    let mut server = listener::SocketServer::bind(&path).inspect_err(|e| {
        crate::diag::record(&format!("could not bind the session socket: {e}"));
    })?;
    crate::diag::record(&format!("serving {} for {}s", path.display(), timeout.as_secs()));

    const CONSECUTIVE_FAILURES_BEFORE_GIVING_UP: u32 = 50;
    let mut failures: u32 = 0;

    while !agent.stopping.load(Ordering::SeqCst) && !agent.expired() {
        match server.accept() {
            Ok(stream) => {
                failures = 0;
                serve_one(&agent, stream);
            }
            Err(e) => {
                failures += 1;
                if failures >= CONSECUTIVE_FAILURES_BEFORE_GIVING_UP {
                    crate::diag::record(&format!(
                        "giving up after {failures} consecutive accept failures; last was: {e}"
                    ));
                    break;
                }
                if failures == 1 {
                    crate::diag::record(&format!("accept failed: {e}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    crate::diag::record(&format!(
        "accept loop ended: stopping={} expired={}",
        agent.stopping.load(Ordering::SeqCst),
        agent.expired()
    ));

    agent.close_open_documents();
    agent.forget();
    Ok(())
}

/// Serve one request; identical to the Windows path but for the stream type.
#[cfg(unix)]
fn serve_one(agent: &Agent, stream: std::os::unix::net::UnixStream) {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }

    let response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(request) => agent.handle(request),
        Err(e) => Response::Error { message: format!("malformed request: {e}") },
    };
    line.zeroize();

    if let Ok(mut encoded) = serde_json::to_string(&response) {
        let mut writer = &stream;
        let _ = writer.write_all(encoded.as_bytes());
        let _ = writer.write_all(b"\n");
        let _ = writer.flush();
        encoded.zeroize();
    }
}

#[cfg(not(any(windows, unix)))]
fn run(_vault: PathBuf, _vault_id: &str, _key: Vec<u8>, _timeout: Duration) -> Result<()> {
    bail!("the encino session agent supports Windows and Unix only")
}
