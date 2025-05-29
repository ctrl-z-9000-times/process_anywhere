//! Tools for running computer processes locally or remotely via SSH.

use ssh2::{Channel, Session, Sftp};
use std::collections::VecDeque;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Ssh(#[from] ssh2::Error),

    #[error("{0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Token representing a computer and how to access it.
#[derive(Clone)]
pub enum Computer {
    /// Local host computer.
    Local,

    /// Remote host computer via the Secure Shell Protocol (SSH).
    Remote {
        /// Hostname of the remote computer.
        host: String,
        addr: SocketAddr,
        user: String,
        auth: String,
        /// The established SSH connection object.
        /// One SSH session multiplexes to service multiple remote processes.
        sess: Option<Session>,
    },
}

impl Computer {
    /// Get the computer that is currently running this program.
    pub fn new_local() -> Self {
        Self::Local
    }
    /// Get a computer remotely over SSH.
    pub fn new_remote(host: String, user: String, auth: String) -> Result<Self, Error> {
        let addr = host.to_socket_addrs()?.next().unwrap();
        Ok(Self::Remote {
            host,
            addr,
            user,
            auth,
            sess: None,
        })
    }
    /// Establish an SSH connection to a remote computer.  
    /// This does nothing on local computers.  
    pub fn connect(&mut self) -> Result<(), Error> {
        // Unpack the remote computer's information into local variables.
        let Self::Remote {
            addr,
            user,
            auth,
            sess,
            ..
        } = self
        else {
            return Ok(());
        };
        // Establish the SSH connection.
        if sess.is_none() {
            let tcp = TcpStream::connect(*addr)?;
            let mut conn = Session::new()?;
            conn.set_tcp_stream(tcp);
            conn.handshake()?;
            conn.userauth_password(user, auth)?;
            conn.set_blocking(false);
            *sess = Some(conn);
        }
        Ok(())
    }
    /// Zero the authentication token / password out of memory.
    fn delete_auth(&mut self) {
        match self {
            Self::Local => {}
            Self::Remote { auth, .. } => {
                // Zero all of the string's data.
                unsafe {
                    let vec = auth.as_mut_vec();
                    vec.set_len(vec.capacity());
                    vec.fill(0);
                }
                auth.clear(); // Zero the size too.
                *auth = String::new(); // Free the memory allocation.
            }
        }
    }
    /// Returns the externally visible hostname of this computer.
    pub fn host(&self) -> String {
        format!("{self}")
    }
    /// Returns an active session if this is a remote computer, or [None] if
    /// this is a local computer.  
    /// Panics if the session has not yet been established.  
    fn get_session(&self) -> Option<&Session> {
        if let Self::Remote { sess, .. } = self {
            Some(sess.as_ref().expect("Session not established"))
        } else {
            None
        }
    }
    pub fn send_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.send_file_inner(path.as_ref())
    }
    fn send_file_inner(&self, path: &Path) -> Result<(), Error> {
        let Some(sess) = self.get_session() else {
            return Ok(());
        };
        sess.set_blocking(true);
        let sftp = sess.sftp()?;
        // Get the remote files's modification time stamp (in unix time).
        let remote_mtime = match sftp.stat(path) {
            Ok(metadata) => metadata.mtime,
            Err(err) => match err.code() {
                // ErrorCode #2 is "file not found" error.
                ssh2::ErrorCode::SFTP(2) => {
                    // Ensure that the parent directory exists.
                    if let Some(dir) = path.parent() {
                        remote_create_dir_all(&sftp, dir, 0o775)?;
                    }
                    None
                }
                _ => return Err(err.into()),
            },
        };
        // Get the local file's modification time stamp (in unix time).
        let local_metadata = std::fs::metadata(path)?;
        let local_mtime = local_metadata.modified()?;
        let local_mtime = local_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Check if the file is already up-to-date on the remote.
        if Some(local_mtime) == remote_mtime {
            return Ok(());
        }
        // Copy the file to the remote computer.
        let data = std::fs::read(path)?;
        let mut remote_file = sftp.create(path)?;
        remote_file.write_all(&data)?;
        // Set the permission bits on the remote.
        #[cfg(target_family = "unix")]
        let perm = {
            use std::os::unix::fs::MetadataExt;
            Some(local_metadata.mode())
        };
        #[cfg(target_family = "windows")]
        let perm = {
            None
            // todo!()
        };
        remote_file.setstat(ssh2::FileStat {
            size: None,
            uid: None,
            gid: None,
            perm,
            atime: None,
            mtime: Some(local_mtime),
        })?;
        Ok(())
    }
    pub fn recv_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.recv_file_inner(path.as_ref())
    }
    fn recv_file_inner(&self, path: &Path) -> Result<(), Error> {
        let Some(sess) = self.get_session() else {
            return Ok(());
        };
        // Create the local parent directory if it doesn't already exist.
        if let Some(directory) = path.parent() {
            std::fs::create_dir_all(directory)?;
        }
        sess.set_blocking(true);
        let sftp = sess.sftp()?;
        let stat = sftp.stat(path)?;
        assert!(!stat.is_dir());
        // Open and retrieve the file from the remote.
        let mut file = sftp.open(path)?;
        let mut data = match stat.size {
            Some(bytes) => String::with_capacity(bytes as usize),
            None => String::new(),
        };
        file.read_to_string(&mut data)?;
        std::fs::write(path, &data)?;
        Ok(())
    }
    /// Argument command is the program path followed by its arguments.
    pub fn exec(self: Arc<Computer>, command: &[impl AsRef<str>]) -> Result<Box<Process>, Error> {
        assert!(!command.is_empty());
        let inner = match self.as_ref() {
            Computer::Local => {
                // Setup the subprocess command.
                let mut cmd = Command::new(command[0].as_ref());
                cmd.args(command[1..].iter().map(|arg| arg.as_ref()));
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                // Spawn the child process.
                let child = cmd.spawn()?;
                // Set to non-blocking mode.
                #[cfg(target_family = "unix")]
                {
                    change_blocking_fd(child.stdout.as_ref().unwrap().as_raw_fd(), false);
                    change_blocking_fd(child.stderr.as_ref().unwrap().as_raw_fd(), false);
                }
                #[cfg(target_family = "windows")]
                {
                    todo!()
                }
                //
                ProcessInner::Local(child)
            }
            Computer::Remote { sess, .. } => {
                // Assemble the command into a single line.
                let mut line = String::with_capacity(
                    command.iter().map(|arg| arg.as_ref().len()).sum::<usize>() + command.len() - 1,
                );
                line.push_str(command[0].as_ref());
                for arg in &command[1..] {
                    line.push(' ');
                    line.push_str(arg.as_ref());
                }
                // Run the program on the remote computer.
                let sess = sess.as_ref().unwrap();
                sess.set_blocking(true);
                let mut channel = sess.channel_session()?;
                channel.exec(&line)?;
                sess.set_blocking(false);
                //
                ProcessInner::Remote(channel)
            }
        };
        Ok(Box::new(Process {
            computer: self,
            stdout_buffer: Default::default(),
            stderr_buffer: Default::default(),
            inner,
        }))
    }
}

fn remote_create_dir_all(sftp: &Sftp, dir: &Path, mode: i32) -> Result<(), Error> {
    // Base case: check if the directory already exists.
    match sftp.stat(dir) {
        Ok(stat) => {
            debug_assert!(stat.is_dir());
        }
        Err(err) => match err.code() {
            // ErrorCode #2 is "file not found" error.
            ssh2::ErrorCode::SFTP(2) => {
                if let Some(parent) = dir.parent() {
                    // Recursively ensure that the parent directory exists.
                    remote_create_dir_all(sftp, parent, mode)?;
                    // Make the target directory.
                    sftp.mkdir(dir, mode)?;
                }
            }
            _ => return Err(err.into()),
        },
    }
    Ok(())
}

impl fmt::Display for Computer {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(fmt, "localhost"),
            Self::Remote { host, addr, .. } => {
                if !host.is_empty() {
                    write!(fmt, "{host}")
                } else {
                    write!(fmt, "{}", addr.ip())
                }
            }
        }
    }
}

impl fmt::Debug for Computer {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => fmt.write_str("Local"),
            Self::Remote {
                host,
                addr,
                user,
                auth,
                sess,
            } => {
                let auth = if auth.is_empty() {
                    format_args!("None")
                } else {
                    format_args!("[hidden]")
                };
                let sess = match sess {
                    None => format_args!("None"),
                    Some(_) => format_args!("Some(ssh2::Session)"),
                };
                fmt.debug_struct("Remote")
                    .field("host", &host)
                    .field("addr", &addr)
                    .field("user", &user)
                    .field("auth", &auth)
                    .field("sess", &sess)
                    .finish()
            }
        }
    }
}

impl Drop for Computer {
    /// Scrub the password on the way out.
    fn drop(&mut self) {
        self.delete_auth();
    }
}

/// Container for an active computer process.  
///
/// This provides an API for interacting with computer processes,
/// regardless of where the computer is located.
///
/// Drop only closes the process's standard input channel.
/// This does not wait for or kill processes when dropped.
#[derive(Debug)]
pub struct Process {
    computer: Arc<Computer>,
    stdout_buffer: VecDeque<u8>,
    stderr_buffer: VecDeque<u8>,
    inner: ProcessInner,
}

enum ProcessInner {
    Local(Child),
    Remote(Channel),
}

impl fmt::Debug for ProcessInner {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(child) => fmt.debug_tuple("Local").field(child).finish(),
            Self::Remote(_channel) => fmt
                .debug_tuple("Remote")
                .field(&format_args!("ssh2::Channel"))
                .finish(),
        }
    }
}

impl Process {
    /// Is this process still running or does it have unread messages on stdout or stderr?
    pub fn is_alive(&mut self) -> Result<bool, Error> {
        dbg!(&self);
        let Self {
            inner,
            stdout_buffer,
            stderr_buffer,
            ..
        } = self;
        match inner {
            ProcessInner::Local(child) => {
                // Check for buffered & uncollected data.
                if !stdout_buffer.is_empty() || !stderr_buffer.is_empty() {
                    return Ok(true);
                }
                // Check for normal exit status code.
                let status = child.try_wait()?;
                if status.is_none() {
                    return Ok(true);
                }
                // Final check for unread messages.
                let stdout_pipe = child
                    .stdout
                    .as_mut()
                    .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?;
                match read_nonblocking(stdout_pipe) {
                    Ok(stdout_data) => {
                        stdout_buffer.append(&mut stdout_data.into());
                        return Ok(true);
                    }
                    Err(err) => {
                        // Ignore EOF errors.
                        if err.kind() != ErrorKind::BrokenPipe {
                            return Err(err.into());
                        }
                    }
                }
                let stderr_pipe = child
                    .stderr
                    .as_mut()
                    .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?;
                match read_nonblocking(stderr_pipe) {
                    Ok(stderr_data) => {
                        stderr_buffer.append(&mut stderr_data.into());
                        return Ok(true);
                    }
                    Err(err) => {
                        // Ignore EOF errors.
                        if err.kind() != ErrorKind::BrokenPipe {
                            return Err(err.into());
                        }
                    }
                }
                //
                Ok(false)
            }
            ProcessInner::Remote(channel) => Ok(!channel.eof()),
        }
    }
    /// Get the computer that this process is running on.
    pub fn computer(&self) -> &Arc<Computer> {
        &self.computer
    }
    fn stdin(&mut self) -> Result<&mut dyn Write, Error> {
        Ok(match &mut self.inner {
            ProcessInner::Local(child) => child
                .stdin
                .as_mut()
                .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?,
            ProcessInner::Remote(channel) => channel,
        })
    }
    fn stdout(&mut self) -> Result<&mut dyn Read, Error> {
        Ok(match &mut self.inner {
            ProcessInner::Local(child) => child
                .stdout
                .as_mut()
                .ok_or(Error::Io(ErrorKind::BrokenPipe.into()))?,
            ProcessInner::Remote(channel) => channel,
        })
    }
    /// Write to and flush the process's standard input channel.
    /// This appends a newline (if not already present).
    pub fn send_line(&mut self, message: &str) -> Result<(), Error> {
        let stdin = self.stdin()?;
        stdin.write_all(message.as_bytes())?;
        if !message.ends_with('\n') {
            stdin.write_all(b"\n")?;
        }
        stdin.flush()?;
        Ok(())
    }
    /// Write to and flush the process's standard input channel.
    pub fn send_bytes(&mut self, message: &[u8]) -> Result<(), Error> {
        let stdin = self.stdin()?;
        stdin.write_all(message)?;
        stdin.flush()?;
        Ok(())
    }
    /// Read zero or one lines from the process's standard output channel.
    pub fn recv_line(&mut self) -> Result<Option<String>, Error> {
        // First check the local buffer.
        let line = read_line(&mut self.stdout_buffer)?;
        if line.is_some() {
            return Ok(line);
        }
        //
        let stdout = self.stdout()?;
        let read_result = read_nonblocking(stdout);
        //
        match read_result {
            Ok(data) => {
                self.stdout_buffer.append(&mut data.into());
                let line = read_line(&mut self.stdout_buffer)?;
                return Ok(line);
            }
            Err(err) => {
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stdout_buffer.is_empty() {
                    let data = std::mem::take(&mut self.stdout_buffer);
                    let line = Some(String::from_utf8(data.into())?);
                    return Ok(line);
                }
                return Err(err.into());
            }
        }
    }
    /// Read zero or one lines from the process's standard error channel.
    pub fn error_line(&mut self) -> Result<Option<String>, Error> {
        // First check the local buffer.
        let line = read_line(&mut self.stderr_buffer)?;
        if line.is_some() {
            return Ok(line);
        }
        //
        let read_result = match &mut self.inner {
            ProcessInner::Local(child) => read_nonblocking(child.stderr.as_mut().unwrap()),
            ProcessInner::Remote(channel) => read_nonblocking(&mut channel.stderr()),
        };
        //
        match read_result {
            Ok(data) => {
                self.stderr_buffer.append(&mut data.into());
                let line = read_line(&mut self.stderr_buffer)?;
                return Ok(line);
            }
            Err(err) => {
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stderr_buffer.is_empty() {
                    let data = std::mem::take(&mut self.stderr_buffer);
                    let line = Some(String::from_utf8(data.into())?);
                    return Ok(line);
                }
                return Err(err.into());
            }
        }
    }
    /// Read an exact number of bytes from the process's standard output channel.
    pub fn recv_bytes(&mut self, bytes: usize) -> Result<Option<Box<[u8]>>, Error> {
        // First check the local buffer.
        if self.stdout_buffer.len() >= bytes {
            return Ok(Some(self.stdout_buffer.drain(..bytes).collect()));
        }
        //
        let stdout = self.stdout()?;
        let chunk = read_nonblocking(stdout)?;
        self.stdout_buffer.append(&mut chunk.into());
        if self.stdout_buffer.len() >= bytes {
            Ok(Some(self.stdout_buffer.drain(..bytes).collect()))
        } else {
            Ok(None)
        }
    }
    /// Read all available bytes from the process's standard error channel.
    pub fn error_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let read_result = match &mut self.inner {
            ProcessInner::Local(child) => read_nonblocking(child.stderr.as_mut().unwrap()),
            ProcessInner::Remote(channel) => read_nonblocking(&mut channel.stderr()),
        };
        match read_result {
            Ok(data) => {
                self.stderr_buffer.append(&mut data.into());
                Ok(self.stderr_buffer.drain(..).collect())
            }
            Err(err) => {
                let eof = err.kind() == ErrorKind::BrokenPipe;
                if eof && !self.stderr_buffer.is_empty() {
                    let data = std::mem::take(&mut self.stderr_buffer);
                    return Ok(data.into());
                }
                return Err(err.into());
            }
        }
    }
    /// Close the process's standard input channel.
    pub fn close_stdin(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            ProcessInner::Local(child) => {
                if let Some(mut pipe) = child.stdin.take() {
                    pipe.flush()?;
                }
            }
            ProcessInner::Remote(channel) => {
                // Block so that it can flush the buffer.
                let sess = self.computer.get_session().unwrap();
                sess.set_blocking(true);
                channel.close()?;
                sess.set_blocking(false);
            }
        }
        Ok(())
    }
    /// Close the process's standard input channel and block until it terminates.
    ///
    /// Returns [true] if the process ended cleanly, or [false] if killed by a
    /// signal or if it exited with non-zero status code.
    pub fn wait(&mut self) -> Result<bool, Error> {
        match &mut self.inner {
            ProcessInner::Local(child) => {
                if let Some(mut pipe) = child.stdin.take() {
                    pipe.flush()?;
                }
                let status = child.wait()?;
                Ok(status.success())
            }
            ProcessInner::Remote(channel) => {
                //
                let sess = self.computer.get_session().unwrap();
                sess.set_blocking(true);
                channel.close()?;
                channel.wait_close()?;
                sess.set_blocking(false);
                //
                let signal = channel.exit_signal()?;
                if signal.exit_signal.is_some() {
                    return Ok(false);
                }
                //
                let status = channel.exit_status()?;
                let success = status == 0;
                return Ok(success);
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _error = self.close_stdin();
    }
}

#[cfg(target_family = "unix")]
fn change_blocking_fd(fd: std::os::unix::io::RawFd, blocking: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            panic!("libc file control error");
        }
        let error = libc::fcntl(
            fd,
            libc::F_SETFL,
            if blocking {
                flags & !libc::O_NONBLOCK
            } else {
                flags | libc::O_NONBLOCK
            },
        );
        if error < 0 {
            panic!("libc file control error");
        }
    }
}

fn read_nonblocking(pipe: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut len = 0;
    let mut buffer = vec![];
    loop {
        buffer.reserve(100);
        unsafe {
            buffer.set_len(buffer.capacity());
        }
        match pipe.read(&mut buffer[len..]) {
            Ok(num) => {
                len += num;
                if len == 0 {
                    return Err(ErrorKind::BrokenPipe.into());
                } else if len < buffer.len() {
                    unsafe {
                        buffer.set_len(len);
                    }
                    return Ok(buffer);
                }
            }
            Err(err) => {
                match err.kind() {
                    ErrorKind::WouldBlock => {
                        unsafe { buffer.set_len(len) };
                        return Ok(buffer);
                    }
                    _ => {
                        return Err(err);
                    }
                };
            }
        }
    }
}

fn read_line(buffer: &mut VecDeque<u8>) -> Result<Option<String>, Error> {
    if let Some(newline) = buffer.iter().position(|&chr| chr == b'\n') {
        let mut tail = buffer.split_off(newline);
        tail.pop_front(); // Discard the separating newline character.
        let line = std::mem::replace(buffer, tail);
        let line = String::from_utf8(line.into())?; // Consume the line even if it fails to parse.
        Ok(Some(line))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    /// Test the custom implementation of the Debug trait.
    #[test]
    fn passwords_hidden() {
        let comp1 = Computer::Local;
        let comp2 = Computer::Remote {
            host: String::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234),
            user: "unit_test".to_string(),
            auth: "Z".to_string(),
            sess: None,
        };

        let debug = format!("{comp1:?}\n{comp2:?}");
        assert!(debug.contains("unit_test"));
        assert!(!debug.contains("Z"));
    }

    #[test]
    fn local_ack() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "-"])).unwrap();
        assert!(proc.is_alive().unwrap());

        // No data yet, should instantly yield (non-blocking).
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        // Send a message. Environment should echo it back to stdout.
        proc.send_line("Hello localhost").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello localhost");

        // Message consumed, no further messages.
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.wait().unwrap());

        assert!(!proc.is_alive().unwrap());
    }

    #[test]
    fn error_line() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "foobar"])).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(proc.is_alive().unwrap());
        assert!(proc.recv_line().is_err());
        assert!(dbg!(proc.error_line()).unwrap().is_some());
        assert!(!proc.wait().unwrap());
        assert!(!proc.is_alive().unwrap());
    }

    #[test]
    fn new_lines() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "-"])).unwrap();
        proc.send_line("Hello\n\n \nlocalhost\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), " ");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "localhost");
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.wait().unwrap());
    }

    #[test]
    fn eof_line() {
        let comp = dbg!(Arc::new(Computer::Local));
        let mut proc = dbg!(comp.exec(&["cat", "-"])).unwrap();
        proc.send_bytes(b"one\ntwo\nthree").unwrap();
        proc.close_stdin().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "one");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "two");
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "three");
        assert!(dbg!(proc.recv_line()).is_err());

        assert!(proc.wait().unwrap());
    }

    fn test_computer() -> Computer {
        Computer::Remote {
            host: String::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 56, 101)), 1234),
            user: "vboxuser".to_string(),
            auth: "testasset321".to_string(),
            sess: None,
        }
    }

    #[test]
    fn remote_ack() {
        // First SCP the environment files onto the remote test computer.
        let mut comp = dbg!(test_computer());
        comp.connect().unwrap();
        let mut proc = dbg!(Arc::new(comp).exec(&["cat".to_string(), "-".to_string()])).unwrap();
        assert!(proc.is_alive().unwrap());

        std::thread::sleep(std::time::Duration::from_millis(100));

        // No data yet, should instantly yield (non-blocking).
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        // Send a message. Environment should echo it back to stdout.
        proc.send_line("Hello remote").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(dbg!(proc.recv_line()).unwrap().unwrap(), "Hello remote");

        // Message consumed, no further messages.
        assert!(matches!(dbg!(proc.recv_line()), Ok(None)));

        assert!(proc.error_bytes().unwrap().is_empty());
        assert!(proc.wait().unwrap());
        assert!(!proc.is_alive().unwrap());
    }

    /// Test sending and receiving files.
    #[test]
    fn remote_roundtrip() {
        let mut comp = dbg!(test_computer());
        comp.connect().unwrap();
        // Make a new local directory.
        let dir_name = PathBuf::from("test_dir");
        std::fs::create_dir_all(&dir_name).unwrap();

        // Make a new local file.
        let file_name = dir_name.join("test_file");
        let file_data = "Hello roundtrip!";
        std::fs::write(&file_name, &file_data).unwrap();

        // Send it to the remote test computer.
        comp.send_file(&file_name).unwrap();

        // Delete the local copy of the file.
        std::fs::remove_file(&file_name).unwrap();
        std::fs::remove_dir(&dir_name).unwrap();

        // Retrieve the file from the remote.
        comp.recv_file(&file_name).unwrap();
        let roundtrip = std::fs::read_to_string(&file_name).unwrap();

        // Cleanup the local files.
        std::fs::remove_file(&file_name).unwrap();
        std::fs::remove_dir(&dir_name).unwrap();

        // Check the contents are correct.
        assert_eq!(file_data, roundtrip);
    }
}
