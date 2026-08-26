//! A Task Scheduler logon task, registered from XML.
//!
//! `schtasks /Create /SC ONLOGON` on the command line would be three lines
//! instead of this file, and it would ship a bug: a task created that way gets
//! the default `ExecutionTimeLimit` of `PT72H`, so Windows would terminate the
//! supervisor after three days and every protected workspace would quietly
//! become writable. There is no command-line switch to change it. `/XML` is the
//! only way to say `PT0S`, and while the file is being written anyway it is also
//! the only way to say `Hidden` — without which every logon opens a console
//! window that sits there for the rest of the session.
//!
//! Per-user and unelevated: the task runs as the user who installed it, with
//! `LeastPrivilege` and an interactive token. Nothing here needs administrator,
//! and a Ralon that asked for it would be handing an agent something better to
//! attack than the files it is guarding.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use super::Registration;

pub const SUPPORTED: bool = true;

/// Shown in Task Scheduler, and the handle for `/Delete`.
const TASK: &str = "Ralon Supervisor";

pub fn install(executable: &Path, home: &Path) -> Result<Registration> {
    let user = account();
    let xml = describe_task(executable, home, &user);

    // A file rather than a pipe: `schtasks /XML` takes a path, and it wants
    // UTF-16 — handed UTF-8 it reports a parse error that names a line number
    // and nothing useful about the encoding.
    let path = std::env::temp_dir().join("ralon-supervisor-task.xml");
    std::fs::write(&path, utf16(&xml))
        .with_context(|| format!("failed to write {}", path.display()))?;

    let created = Command::new("schtasks")
        .args(["/Create", "/TN", TASK, "/XML"])
        .arg(&path)
        .arg("/F")
        .output()
        .context("failed to run schtasks — is it on PATH?")?;
    let _ = std::fs::remove_file(&path);

    if !created.status.success() {
        anyhow::bail!(
            "schtasks refused to register the supervisor: {}",
            message(&created)
        );
    }

    // Registered is not running: the trigger is the *next* logon, and a
    // developer who just ran `ralon install` is owed enforcement now rather
    // than after a reboot.
    let mut warnings = Vec::new();
    let started = Command::new("schtasks")
        .args(["/Run", "/TN", TASK])
        .output()
        .context("failed to run schtasks")?;
    if !started.status.success() {
        warnings.push(format!(
            "the task is registered but would not start now ({}) — it will start at \
             the next logon, or run `ralon daemon` in a terminal to see why",
            message(&started)
        ));
    }

    Ok(Registration {
        mechanism: "a Task Scheduler logon task",
        path: None,
        warnings,
    })
}

pub fn uninstall() -> Result<bool> {
    if !installed() {
        return Ok(false);
    }
    // Ends the running instance first. Deleting a task does not stop it, and a
    // supervisor left running with no registration is the one state nothing
    // would ever report.
    let _ = Command::new("schtasks")
        .args(["/End", "/TN", TASK])
        .output();

    let removed = Command::new("schtasks")
        .args(["/Delete", "/TN", TASK, "/F"])
        .output()
        .context("failed to run schtasks")?;
    if !removed.status.success() {
        anyhow::bail!(
            "schtasks would not remove the supervisor task: {}",
            message(&removed)
        );
    }
    Ok(true)
}

pub fn installed() -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", TASK])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn unsupported_reason() -> String {
    String::new()
}

/// `DOMAIN\user`, which both the trigger and the principal have to name.
///
/// Falls back to the machine name, which is what `USERDOMAIN` holds on a
/// machine that has never been joined to anything.
fn account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    }
}

fn describe_task(executable: &Path, home: &Path, user: &str) -> String {
    let command = escape(&executable.display().to_string());
    let arguments = escape(&format!("daemon --home \"{}\"", home.display()));
    let user = escape(user);

    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Ralon enforces agent.lock in the workspaces registered with `ralon install`.</Description>
    <URI>\{TASK}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// XML entity escaping. A path can hold `&`, and a user name on a domain can
/// hold most of the rest.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// UTF-16LE with a byte order mark, which is what `schtasks /XML` reads.
fn utf16(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// `schtasks` writes its complaint to stdout about as often as to stderr.
fn message(output: &std::process::Output) -> String {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let trimmed = combined.trim();
    if trimmed.is_empty() {
        format!("exit code {}", output.status.code().unwrap_or(-1))
    } else {
        trimmed.replace('\r', "").replace('\n', " ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_task_never_expires() {
        let xml = describe_task(
            Path::new("C:\\ralon.exe"),
            Path::new("C:\\state"),
            "PC\\dev",
        );
        // The whole reason this file exists rather than a `schtasks /Create`
        // one-liner: the default is PT72H, and a supervisor that stops after
        // three days unprotects every workspace without saying anything.
        assert!(
            xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"),
            "{xml}"
        );
        assert!(xml.contains("<Hidden>true</Hidden>"), "{xml}");
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{xml}");
    }

    #[test]
    fn the_state_directory_is_passed_rather_than_inherited() {
        let xml = describe_task(
            Path::new("C:\\ralon.exe"),
            Path::new("C:\\state"),
            "PC\\dev",
        );
        assert!(xml.contains("daemon --home &quot;C:\\state&quot;"), "{xml}");
    }

    #[test]
    fn markup_in_a_path_cannot_break_out_of_the_element() {
        let xml = describe_task(
            Path::new("C:\\a&b\\ralon.exe"),
            Path::new("C:\\state"),
            "PC\\dev",
        );
        assert!(xml.contains("C:\\a&amp;b\\ralon.exe"), "{xml}");
    }

    #[test]
    fn the_document_is_utf16_with_a_byte_order_mark() {
        let bytes = utf16("<a/>");
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(&bytes[2..4], &[b'<', 0]);
    }
}
