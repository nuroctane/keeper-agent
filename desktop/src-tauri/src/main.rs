#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(debug_assertions)]
use std::path::Path;
use std::{path::PathBuf, process::Stdio, sync::Mutex, time::Duration};
use tauri::{Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default, Serialize, Deserialize, Clone)]
struct Preferences {
    state_path: Option<PathBuf>,
}
struct DesktopState {
    preferences: Mutex<Preferences>,
    gate: tokio::sync::Mutex<()>,
}

fn state_path(app: &tauri::AppHandle, state: &DesktopState) -> Result<PathBuf, String> {
    let prefs = state
        .preferences
        .lock()
        .map_err(|_| "Settings unavailable")?;
    prefs.state_path.clone().map(Ok).unwrap_or_else(|| {
        app.path()
            .app_local_data_dir()
            .map(|p| p.join("broker"))
            .map_err(|_| "Application folder unavailable".into())
    })
}
fn helper(app: &tauri::AppHandle) -> Result<(PathBuf, Vec<String>), String> {
    let exe = std::env::current_exe().map_err(|_| "Application path unavailable")?;
    let name = if cfg!(windows) {
        "keeper-agent-core.exe"
    } else {
        "keeper-agent-core"
    };
    if let Ok(resources) = app.path().resource_dir() {
        let packaged = resources.join("core").join(name);
        if packaged.is_file() {
            return Ok((packaged, vec![]));
        }
    }
    if let Some(parent) = exe.parent() {
        let bundled = parent.join(name);
        if bundled.is_file() {
            return Ok((bundled, vec![]));
        }
    }
    // Development uses only the repository-owned virtual environment, never PATH.
    #[cfg(debug_assertions)]
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("Repository path unavailable")?;
        let python = root.join(if cfg!(windows) {
            ".venv/Scripts/python.exe"
        } else {
            ".venv/bin/python"
        });
        if python.is_file() {
            return Ok((python, vec!["-m".into(), "keeper_agent.desktop".into()]));
        }
    }
    Err("Broker runtime is missing. Run desktop setup or install a complete packaged build.".into())
}

#[tauri::command]
async fn desktop_request(
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    mut request: Value,
) -> Result<Value, String> {
    let _guard = state.gate.lock().await;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("Invalid operation")?;
    if ![
        "snapshot",
        "initialize",
        "get_action",
        "save_action",
        "delete_action",
        "create_client",
        "revoke_client",
        "run",
    ]
    .contains(&operation)
    {
        return Err("Unsupported operation".into());
    }
    request
        .as_object_mut()
        .ok_or("Invalid request")?
        .insert("state".into(), json!(state_path(&app, &state)?));
    let input = serde_json::to_vec(&request).map_err(|_| "Invalid request")?;
    if input.len() > 1_048_576 {
        return Err("Request is too large".into());
    }
    let (binary, args) = helper(&app)?;
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(debug_assertions)]
    command.current_dir(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap(),
    );
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command
        .spawn()
        .map_err(|_| "Could not start the broker runtime")?;
    let task = async {
        let mut stdin = child.stdin.take().ok_or("Runtime input unavailable")?;
        stdin
            .write_all(&input)
            .await
            .map_err(|_| "Runtime input failed")?;
        drop(stdin);
        let stdout = child.stdout.take().ok_or("Runtime output unavailable")?;
        let mut output = Vec::new();
        stdout
            .take(1_048_577)
            .read_to_end(&mut output)
            .await
            .map_err(|_| "Runtime output failed")?;
        if output.len() > 1_048_576 {
            return Err("Runtime output exceeded limit".to_string());
        }
        child.wait().await.map_err(|_| "Runtime failed")?;
        let response: Value =
            serde_json::from_slice(&output).map_err(|_| "Runtime returned an invalid response")?;
        if response.get("ok") == Some(&Value::Bool(true)) {
            Ok(response["data"].clone())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Operation failed")
                .to_owned())
        }
    };
    tokio::time::timeout(Duration::from_secs(345), task)
        .await
        .map_err(|_| "Operation timed out".to_string())?
}

#[tauri::command]
fn set_state_path(
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    path: PathBuf,
) -> Result<(), String> {
    if !path.is_absolute() || !path.join("keeper.json").is_file() {
        return Err("Choose an initialized broker folder containing keeper.json".into());
    }
    let path = path.canonicalize().map_err(|_| "Folder unavailable")?;
    let prefs = Preferences {
        state_path: Some(path),
    };
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|_| "Settings folder unavailable")?;
    std::fs::create_dir_all(&dir).map_err(|_| "Could not save settings")?;
    std::fs::write(
        dir.join("desktop.json"),
        serde_json::to_vec(&prefs).unwrap(),
    )
    .map_err(|_| "Could not save settings")?;
    *state
        .preferences
        .lock()
        .map_err(|_| "Settings unavailable")? = prefs;
    Ok(())
}

/// PowerShell also ends single-quoted strings at typographic single quotes, so
/// each of them is doubled like the ASCII quote.
#[cfg(any(windows, test))]
fn powershell_quote(s: &str) -> String {
    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::powershell_quote;

    #[test]
    fn powershell_quote_doubles_every_single_quote_form() {
        assert_eq!(powershell_quote("C:\\plain"), "'C:\\plain'");
        assert_eq!(powershell_quote("it's"), "'it''s'");
        assert_eq!(
            powershell_quote("a\u{2019}; calc; \u{2018}b"),
            "'a\u{2019}\u{2019}; calc; \u{2018}\u{2018}b'"
        );
        assert_eq!(powershell_quote("\u{201A}\u{201B}"), "'\u{201A}\u{201A}\u{201B}\u{201B}'");
    }
}

#[cfg(target_os = "macos")]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[tauri::command]
fn login_terminal(app: tauri::AppHandle, state: State<'_, DesktopState>) -> Result<(), String> {
    let folder = state_path(&app, &state)?;
    if !folder.join("keeper.json").is_file() {
        return Err("Set up a broker folder first".into());
    }
    open_terminal(
        &app,
        vec![
            "serve".to_owned(),
            "--state".to_owned(),
            folder.to_string_lossy().into_owned(),
        ],
    )
}

#[tauri::command]
fn browser_setup_terminal(app: tauri::AppHandle) -> Result<(), String> {
    open_terminal(&app, vec!["install-browser".to_owned()])
}

fn open_terminal(app: &tauri::AppHandle, extra: Vec<String>) -> Result<(), String> {
    let (binary, mut args) = helper(app)?;
    args.extend(extra);
    #[cfg(windows)]
    {
        use base64::Engine;
        use std::os::windows::process::CommandExt;
        let line = format!(
            "& {} {}",
            powershell_quote(&binary.to_string_lossy()),
            args.iter()
                .map(|s| powershell_quote(s))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            line.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let powershell = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .ok_or("Windows folder unavailable")?
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        std::process::Command::new(powershell)
            .args(["-NoProfile", "-NoExit", "-EncodedCommand", &encoded])
            .creation_flags(0x00000010)
            .spawn()
            .map_err(|_| "Could not open the private terminal")?;
    }
    #[cfg(target_os = "macos")]
    {
        let line = format!(
            "{} {}",
            shell_quote(&binary.to_string_lossy()),
            args.iter()
                .map(|s| shell_quote(s))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let apple = line.replace('\\', "\\\\").replace('"', "\\\"");
        std::process::Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!("tell application \"Terminal\" to do script \"{}\"", apple),
            ])
            .spawn()
            .map_err(|_| "Could not open Terminal")?;
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    return Err("Open keeper-agent serve manually on this platform".into());
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let prefs = app
                .path()
                .app_config_dir()
                .ok()
                .and_then(|p| std::fs::read(p.join("desktop.json")).ok())
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            app.manage(DesktopState {
                preferences: Mutex::new(prefs),
                gate: tokio::sync::Mutex::new(()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            desktop_request,
            set_state_path,
            login_terminal,
            browser_setup_terminal
        ])
        .run(tauri::generate_context!())
        .expect("Could not launch Keeper Agent");
}
