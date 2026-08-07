//! A named pipe server restricted to one account.
//!
//! Each client gets its own pipe instance. With a single reused instance, the
//! next client binds the moment the previous one closes, and the server's
//! `DisconnectNamedPipe` for the finished transaction tears down that new
//! client's connection.
//!
//! Creating the replacement instance immediately after accepting is not enough
//! either. Between `ConnectNamedPipe` returning and the replacement existing,
//! every instance of the name is connected, and a client calling `CreateFileW`
//! in that window is refused with `ERROR_PIPE_BUSY`. The client retries, so the
//! fault is invisible in practice, but a window that has to be *timed* to hit
//! can only ever be tested probabilistically.
//!
//! This server therefore keeps a spare instance listening at all times: it
//! serves `current`, promotes `spare`, and only then creates a new spare. At no
//! instant does the name lack a listening instance, so the window does not
//! exist rather than being merely unlikely, and the invariant is testable
//! without timing anything — see the tests at the foot of this file.

use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;

use crate::win::PipeSecurity;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Bytes buffered in each direction; requests and replies are single JSON lines.
const BUFFER_SIZE: u32 = 8 * 1024;

/// A named pipe only the owning account may open.
///
/// Two instances are held: `current`, which the next `accept` waits on, and
/// `spare`, which is already listening so an arriving client never finds the
/// name fully occupied.
pub struct PipeServer {
    name: Vec<u16>,
    current: HANDLE,
    spare: HANDLE,
    security: PipeSecurity,
}

impl PipeServer {
    /// Create the pipe, failing if one of this name already exists.
    ///
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` fails when the name is taken, so a
    /// squatter cannot answer this agent's clients; only the first instance may
    /// carry it, which is also why the spare must not.
    /// `PIPE_REJECT_REMOTE_CLIENTS` refuses connections over the network.
    pub fn create(name: &str, owner_sid: &str) -> io::Result<Self> {
        let security = PipeSecurity::for_sid(owner_sid)?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        let current = create_instance(&wide, &security, true)?;
        let spare = match create_instance(&wide, &security, false) {
            Ok(spare) => spare,
            Err(e) => {
                // SAFETY: closing the instance just created, before it escapes.
                unsafe { CloseHandle(current) };
                return Err(e);
            }
        };

        Ok(PipeServer { name: wide, current, spare, security })
    }

    /// Wait for a client and return its connection.
    pub fn accept(&mut self) -> io::Result<PipeConnection> {
        // SAFETY: `self.current` is a valid pipe instance owned by this server.
        let connected = unsafe { ConnectNamedPipe(self.current, std::ptr::null_mut()) };

        if connected == 0 {
            let error = io::Error::last_os_error();
            // A client that attached before this call — to this instance while
            // it was the spare, for one — is success, not failure.
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                return Err(error);
            }
        }

        // Build the new spare before touching any state: on failure the server
        // must be left exactly as it was, or `self.current` would keep a handle
        // already connected to a client and the next `accept` would hand out a
        // connection to somebody who has gone.
        let replacement = create_instance(&self.name, &self.security, false)?;

        let served = self.current;
        self.current = std::mem::replace(&mut self.spare, replacement);

        Ok(PipeConnection { handle: served })
    }
}

// SAFETY: the server owns its two handles exclusively, and a Win32 handle is a
// process-wide kernel reference usable from any thread. Nothing here is a
// pointer into this thread's memory.
unsafe impl Send for PipeServer {}

impl Drop for PipeServer {
    fn drop(&mut self) {
        for handle in [self.current, self.spare] {
            if handle != INVALID_HANDLE_VALUE {
                // SAFETY: closing a handle this type owns, exactly once.
                unsafe { CloseHandle(handle) };
            }
        }
    }
}

fn create_instance(name: &[u16], security: &PipeSecurity, first: bool) -> io::Result<HANDLE> {
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    // SAFETY: `name` is NUL-terminated UTF-16 and `security` is borrowed from the
    // server that owns it, so both outlive this call.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            security.as_ptr().cast_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

/// One accepted client connection, owning its own pipe instance. Reads and
/// writes go through a borrowed [`File`] rather than further hand-written FFI.
pub struct PipeConnection {
    handle: HANDLE,
}

impl PipeConnection {
    /// Wait until this client has sent a whole line, or `timeout` passes.
    ///
    /// `false` means give up on the connection instead of reading it: a blocking
    /// pipe read has no deadline of its own, so a client that attaches and then
    /// says nothing would otherwise hold the agent's accept loop indefinitely.
    pub fn wait_for_request(&self, timeout: std::time::Duration) -> bool {
        // SAFETY: this connection owns `handle` and does not close it until
        // Drop, so it is live for the whole call.
        unsafe { crate::win::wait_for_line(self.handle, timeout) }
    }

    fn as_file(&self) -> std::mem::ManuallyDrop<File> {
        // SAFETY: the handle outlives the borrow, and `ManuallyDrop` stops the
        // `File` closing a handle it does not own.
        std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(self.handle.cast()) })
    }
}

impl io::Read for &PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self.as_file(), buf)
    }
}

impl io::Write for &PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self.as_file(), buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut &*self.as_file())
    }
}

// SAFETY: as for `PipeServer` — one owned handle, no thread-local state.
unsafe impl Send for PipeConnection {}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        // SAFETY: `handle` is this connection's own pipe instance, released once.
        // Flushing first is required or the last write can be discarded.
        unsafe {
            FlushFileBuffers(self.handle);
            DisconnectNamedPipe(self.handle);
            CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write as _};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// Pipe names are machine-global, so tests that shared one would collide
    /// with each other and with any other copy of the suite.
    fn unique_name() -> String {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\encino-test-{}-{n}", std::process::id())
    }

    fn server() -> (PipeServer, String) {
        let name = unique_name();
        let sid = crate::win::current_user_sid().unwrap();
        let server = PipeServer::create(&name, &sid).unwrap();
        (server, name)
    }

    /// Attach as a client, with none of the retrying the real client does. A
    /// test that retried could not tell a working pipe from a busy one.
    fn connect(name: &str) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new().read(true).write(true).open(name)
    }

    /// Answer `count` clients, echoing one line to each.
    fn serve(mut server: PipeServer, count: usize) {
        for _ in 0..count {
            let connection = server.accept().expect("accept");
            let mut line = String::new();
            BufReader::new(&connection).read_line(&mut line).expect("read request");
            let mut writer = &connection;
            writer.write_all(line.as_bytes()).expect("write reply");
            writer.flush().expect("flush reply");
        }
    }

    fn send(client: &mut std::fs::File, message: &str) {
        client.write_all(format!("{message}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    }

    fn receive(client: &mut std::fs::File) -> String {
        let mut reply = String::new();
        BufReader::new(client).read_line(&mut reply).unwrap();
        reply.trim().to_string()
    }

    fn round_trip(client: &mut std::fs::File, message: &str) -> String {
        send(client, message);
        receive(client)
    }

    /// Serve `count` clients on another thread. The returned closure waits for
    /// that thread, failing rather than hanging if it never finishes.
    ///
    /// The bug this guards against — a client attaching to an instance the
    /// server never waits on — presents as a thread that blocks forever, and a
    /// suite that hangs tells you far less than one that fails.
    ///
    /// The waiting has to happen *after* the client half of the exchange, not
    /// around it, or the test deadlocks on itself: the server cannot finish
    /// until requests arrive, and they arrive from this thread.
    fn served_in_background(server: PipeServer, count: usize) -> impl FnOnce() {
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            serve(server, count);
            let _ = done.send(());
        });

        move || match wait.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout) => {
                panic!("timed out: a client attached to an instance the server never serves")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the serving thread panicked"),
        }
    }

    #[test]
    fn a_request_and_its_reply_survive_the_pipe() {
        let (server, name) = server();
        std::thread::spawn(move || serve(server, 1));

        let mut client = connect(&name).unwrap();
        assert_eq!(round_trip(&mut client, "status"), "status");
    }

    #[test]
    fn two_clients_can_attach_before_the_server_accepts_either() {
        let (server, name) = server();

        // The invariant that makes the window inside `accept` impossible rather
        // than merely unlikely: the name always has an instance free. With a
        // single instance the second of these is refused with ERROR_PIPE_BUSY.
        let mut first = connect(&name).expect("first client");
        let mut second = connect(&name).expect("second client, with no accept in between");

        // And exactly two, which is what makes the assertion above meaningful:
        // instances are finite, so the second client succeeding is the spare
        // doing its job rather than the pipe admitting all comers.
        const ERROR_PIPE_BUSY: i32 = 231;
        let third = connect(&name).expect_err("a third client, with both instances taken");
        assert_eq!(third.raw_os_error(), Some(ERROR_PIPE_BUSY));

        // Both requests go out before the server starts, so the test does not
        // depend on which instance the server happens to accept first.
        send(&mut first, "one");
        send(&mut second, "two");

        let finished = served_in_background(server, 2);
        assert_eq!(receive(&mut first), "one");
        assert_eq!(receive(&mut second), "two");
        finished();
    }

    #[test]
    fn the_spare_is_replenished_so_the_invariant_holds_in_the_steady_state() {
        let (mut server, name) = server();

        // Drive one full transaction, then assert the same property again: a
        // freshly created server is the easy case, and the one that matters is
        // the server that has been serving for hours.
        let mut client = connect(&name).unwrap();
        let worker = std::thread::spawn(move || {
            let connection = server.accept().expect("accept");
            let mut line = String::new();
            BufReader::new(&connection).read_line(&mut line).expect("read");
            let mut writer = &connection;
            writer.write_all(line.as_bytes()).unwrap();
            writer.flush().unwrap();
            drop(connection);
            server
        });
        assert_eq!(round_trip(&mut client, "first"), "first");
        let server = worker.join().unwrap();

        let mut third = connect(&name).expect("client after one accept");
        let mut fourth = connect(&name).expect("second client after one accept");
        send(&mut third, "three");
        send(&mut fourth, "four");

        let finished = served_in_background(server, 2);
        assert_eq!(receive(&mut third), "three");
        assert_eq!(receive(&mut fourth), "four");
        finished();
    }

    #[test]
    fn a_served_connection_closing_does_not_disturb_the_next_client() {
        let (server, name) = server();
        std::thread::spawn(move || serve(server, 2));

        // Each client owns its own instance, so the server's DisconnectNamedPipe
        // for a finished transaction must not reach the next client.
        let mut first = connect(&name).unwrap();
        assert_eq!(round_trip(&mut first, "first"), "first");
        drop(first);

        let mut second = connect(&name).unwrap();
        assert_eq!(round_trip(&mut second, "second"), "second");
    }

    #[test]
    fn a_client_that_says_nothing_is_given_up_on_rather_than_waited_for() {
        let (mut server, name) = server();

        // Attaches and then goes quiet. A blocking read would sit here until the
        // session expired, and every other command would queue behind it.
        let _silent = connect(&name).expect("client");
        let connection = server.accept().expect("accept");

        let started = std::time::Instant::now();
        assert!(!connection.wait_for_request(Duration::from_millis(200)));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait was not bounded: took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_client_that_does_send_a_request_is_not_given_up_on() {
        // The bound above must not have made the ordinary case flaky.
        let (mut server, name) = server();
        let mut client = connect(&name).unwrap();
        send(&mut client, "status");

        let connection = server.accept().expect("accept");
        assert!(connection.wait_for_request(Duration::from_secs(5)));

        // And peeking must not have consumed it.
        let mut line = String::new();
        BufReader::new(&connection).read_line(&mut line).expect("read request");
        assert_eq!(line.trim(), "status");
    }

    #[test]
    fn a_squatter_cannot_take_over_a_name_already_in_use() {
        let (_server, name) = server();
        let sid = crate::win::current_user_sid().unwrap();

        // FILE_FLAG_FIRST_PIPE_INSTANCE on the first instance is what stops
        // another process answering this agent's clients.
        assert!(PipeServer::create(&name, &sid).is_err());
    }

    // Not tested: that the descriptor denies other accounts. That needs a second
    // user account and cannot be done in-process, so it is left to review of
    // `PipeSecurity::for_sid` rather than approximated by an assertion that
    // would pass without proving anything.
}
