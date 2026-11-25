use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use thiserror::Error;
use uuid::Uuid;

/// Windows Task Scheduler task name used for elevated NetFlow logon auto-start.
pub const AUTOSTART_TASK_NAME: &str = "NetFlowAutoStart";

/// CLI argument passed to NetFlow when launched by Windows Task Scheduler at logon.
pub const AUTOSTART_ARG: &str = "--autostart";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Errors returned by [`AutoStartManager`] implementations.
#[derive(Debug, Error)]
pub enum AutoStartError {
    #[error("invalid executable path for auto-start: '{0}'")]
    InvalidExecutablePath(String),
    #[error("auto-start command failed: {0}")]
    CommandFailed(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("Windows Task Scheduler auto-start is only supported on Windows")]
    UnsupportedPlatform,
}

/// Abstraction over OS-level elevated logon auto-start registration.
pub trait AutoStartManager: Send + Sync {
    /// Returns `true` if the logon auto-start registration is currently active.
    fn is_enabled(&self) -> Result<bool, AutoStartError>;

    /// Enables or disables logon auto-start for `exe_path`.
    fn set_enabled(&self, enabled: bool, exe_path: &Path) -> Result<(), AutoStartError>;
}

/// Escapes special XML characters in text content.
fn escape_xml_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Builds a Windows Task Scheduler v1.2 XML definition that launches NetFlow at logon
/// with `HighestAvailable` privileges and no battery/time limits.
pub fn build_task_scheduler_xml(exe_path: &Path, args: &str) -> Result<String, AutoStartError> {
    let exe_str = exe_path.to_str().map(str::trim).unwrap_or("");
    if exe_str.is_empty() {
        return Err(AutoStartError::InvalidExecutablePath(
            exe_path.display().to_string(),
        ));
    }

    let working_dir = exe_path
        .parent()
        .and_then(Path::to_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let escaped_exe = escape_xml_text(exe_str);
    let escaped_args = escape_xml_text(args.trim());
    let escaped_dir = escape_xml_text(working_dir);

    let working_dir_xml = if escaped_dir.is_empty() {
        String::new()
    } else {
        format!("\n      <WorkingDirectory>{escaped_dir}</WorkingDirectory>")
    };
    let args_xml = if escaped_args.is_empty() {
        String::new()
    } else {
        format!("\n      <Arguments>{escaped_args}</Arguments>")
    };

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escaped_exe}</Command>{args_xml}{working_dir_xml}
    </Exec>
  </Actions>
</Task>
"#
    ))
}

/// Real Windows Task Scheduler (`schtasks.exe`) implementation of [`AutoStartManager`].
#[derive(Debug, Clone)]
pub struct WindowsTaskSchedulerAutoStart {
    task_name: String,
}

impl Default for WindowsTaskSchedulerAutoStart {
    fn default() -> Self {
        Self {
            task_name: AUTOSTART_TASK_NAME.to_string(),
        }
    }
}

impl WindowsTaskSchedulerAutoStart {
    /// Creates a manager targeting a custom Task Scheduler task name.
    pub fn new(task_name: impl Into<String>) -> Self {
        Self {
            task_name: task_name.into(),
        }
    }

    /// Returns the Task Scheduler task name managed by this instance.
    pub fn task_name(&self) -> &str {
        &self.task_name
    }
}

fn encode_utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn new_schtasks_command() -> Command {
    let mut cmd = Command::new("schtasks.exe");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

impl AutoStartManager for WindowsTaskSchedulerAutoStart {
    #[cfg(windows)]
    fn is_enabled(&self) -> Result<bool, AutoStartError> {
        let output = new_schtasks_command()
            .args(["/Query", "/TN", &self.task_name])
            .output()?;
        Ok(output.status.success())
    }

    #[cfg(not(windows))]
    fn is_enabled(&self) -> Result<bool, AutoStartError> {
        Err(AutoStartError::UnsupportedPlatform)
    }

    #[cfg(windows)]
    fn set_enabled(&self, enabled: bool, exe_path: &Path) -> Result<(), AutoStartError> {
        if !enabled {
            if !self.is_enabled()? {
                return Ok(());
            }
            let output = new_schtasks_command()
                .args(["/Delete", "/TN", &self.task_name, "/F"])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let detail = if stderr.is_empty() { stdout } else { stderr };
                return Err(AutoStartError::CommandFailed(detail));
            }
            return Ok(());
        }

        if !exe_path.is_file() {
            return Err(AutoStartError::InvalidExecutablePath(
                exe_path.display().to_string(),
            ));
        }

        let xml = build_task_scheduler_xml(exe_path, AUTOSTART_ARG)?;
        let tmp_path = std::env::temp_dir().join(format!(
            "netflow-autostart-{}.xml",
            Uuid::new_v4()
        ));
        fs::write(&tmp_path, encode_utf16le_with_bom(&xml))?;

        let output = new_schtasks_command()
            .args(["/Create", "/TN", &self.task_name, "/XML"])
            .arg(&tmp_path)
            .arg("/F")
            .output();

        let _ = fs::remove_file(&tmp_path);

        let output = output?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            return Err(AutoStartError::CommandFailed(detail));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn set_enabled(&self, _enabled: bool, _exe_path: &Path) -> Result<(), AutoStartError> {
        Err(AutoStartError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_task_scheduler_xml_escapes_paths_and_sets_elevated_logon_settings() {
        let exe = PathBuf::from(r#"C:\Program Files\NetFlow & Co\Net"Flow.exe"#);
        let xml = build_task_scheduler_xml(&exe, AUTOSTART_ARG).expect("valid xml");

        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-16"?>"#));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<Arguments>--autostart</Arguments>"));
        assert!(xml.contains(
            r"<Command>C:\Program Files\NetFlow &amp; Co\Net&quot;Flow.exe</Command>"
        ));
        assert!(xml.contains(
            r"<WorkingDirectory>C:\Program Files\NetFlow &amp; Co</WorkingDirectory>"
        ));
    }

    #[test]
    fn test_build_task_scheduler_xml_rejects_empty_path() {
        let err = build_task_scheduler_xml(Path::new("   "), AUTOSTART_ARG)
            .expect_err("empty exe path should fail");
        assert!(matches!(err, AutoStartError::InvalidExecutablePath(_)));
    }

    #[test]
    fn test_encode_utf16le_with_bom_roundtrips() {
        let sample = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task>NetFlow — UTF16</Task>";
        let encoded = encode_utf16le_with_bom(sample);
        assert_eq!(&encoded[..2], &[0xFF, 0xFE]);
        let units: Vec<u16> = encoded[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        assert_eq!(String::from_utf16(&units).expect("valid utf-16"), sample);
    }
}
