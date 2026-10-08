//! The one sandbox the judge uses for anything that compiles or runs candidate source.
use std::path::{Path, PathBuf};
use std::process::Command;

/// `cargo <args>` for `tree` inside bubblewrap: no network, a cleared environment, no view of the
/// judge's home (where its signing key lives), the tree read-only at `/src`, only `target`
/// writable (at `/target`, which must exist), and the toolchain read-only. Build scripts, proc
/// macros, `include_bytes!` and the candidate's own tests run or read here, so they cannot reach
/// the key. There is no fallback: if the sandbox cannot start, the command fails.
pub fn sandboxed_cargo(tree: &Path, target: &Path, args: &[&str]) -> Command {
    let env_dir = |var: &str, default: &str| -> Option<PathBuf> {
        std::env::var_os(var)
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(default)))
            .filter(|p| p.is_dir())
    };
    // Never expose the judge's home (or a directory holding it) inside the sandbox.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let safe = |d: &PathBuf| home.as_ref().is_none_or(|h| !h.starts_with(d));
    let rustup_home = env_dir("RUSTUP_HOME", ".rustup").filter(safe);
    let cargo_home = env_dir("CARGO_HOME", ".cargo").filter(safe);
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    let cargo_dir = path
        .split(':')
        .map(PathBuf::from)
        .find(|d| d.join("cargo").is_file())
        .filter(safe);
    let mut cmd = Command::new("bwrap");
    cmd.args([
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--die-with-parent",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]);
    for sys in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        if Path::new(sys).exists() {
            cmd.args(["--ro-bind", sys, sys]);
        }
    }
    let mut path_in = vec!["/usr/bin".to_string(), "/bin".to_string()];
    for d in [&rustup_home, &cargo_home, &cargo_dir]
        .into_iter()
        .flatten()
    {
        cmd.arg("--ro-bind").arg(d).arg(d);
    }
    if let Some(d) = &cargo_dir {
        path_in.insert(0, d.display().to_string());
    }
    if let Some(d) = &rustup_home {
        cmd.arg("--setenv").arg("RUSTUP_HOME").arg(d);
    }
    if let Some(d) = &cargo_home {
        cmd.arg("--setenv").arg("CARGO_HOME").arg(d);
    }
    cmd.arg("--ro-bind").arg(tree).arg("/src");
    cmd.arg("--bind").arg(target).arg("/target");
    cmd.args(["--setenv", "PATH", &path_in.join(":")]);
    cmd.args([
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "CARGO_TARGET_DIR",
        "/target",
    ]);
    cmd.args(["--chdir", "/src", "cargo"]);
    cmd.args(args);
    cmd
}
