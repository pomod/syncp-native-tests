use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::process::{Child, Stdio};

pub struct OwnedFixture {
    child: Option<Child>,
    last_exit: Option<i32>,
    failed: bool,
}

impl OwnedFixture {
    pub fn new() -> Self { Self { child: None, last_exit: None, failed: false } }

    pub fn observe(&mut self) -> io::Result<Value> {
        if let Some(child) = self.child.as_mut() {
            if let Some(status) = child.try_wait()? {
                self.last_exit = status.code();
                self.failed = !status.success();
                self.child = None;
            }
        }
        Ok(json!({"id":"owned-acceptance-process", "purpose":"harmless lifecycle proof, not an inference runtime",
            "installed":true,"configured":true,"running":self.child.is_some(),
            "healthy":null,"failed":self.failed,"last_exit_code":self.last_exit,
            "pid":self.child.as_ref().map(Child::id),"ownership":"spawned child handle only","native_ownership":self.child.as_ref().map(crate::platform::owned_identity),"task_timeout_seconds":0}))
    }

    pub fn start(&mut self) -> io::Result<()> {
        self.observe()?;
        if self.child.is_some() { return Ok(()); }
        // A source-defined test recipe only. The API accepts no executable, PID, path or shell command.
        let child = crate::platform::fixture_command()?
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        self.last_exit = None;
        self.failed = false;
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            // Closing the owned stdin also stops this fixed fixture. A BrokenPipe after an
            // unexpected exit must not lose the handle or prevent reaping the child.
            if let Some(mut input) = child.stdin.take() {
                if let Err(error) = input.write_all(b"stop\n") {
                    if error.kind() != io::ErrorKind::BrokenPipe {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                }
            }
            let status = child.wait()?;
            self.last_exit = status.code();
            self.failed = !status.success();
        }
        Ok(())
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        // Only the exact owned handle; never enumerate or terminate by name/port/persisted PID.
        if let Some(child) = self.child.as_mut() { let _ = child.kill(); let _ = child.wait(); }
    }
}

pub fn fixture_child() -> i32 {
    for line in io::stdin().lock().lines() {
        match line.as_deref() {
            Ok("stop") => return 0,
            Ok("fail") => return 17,
            Err(_) => return 2,
            _ => {}
        }
    }
    0
}
