//! Real-diff gate for the ratifier.
//!
//! The ratifier never trusts the file name a proposal declares. It builds the
//! candidate commit off to the side (temporary index, no checkout, no branch
//! moved), asks git for the actual changed entries between the base commit and
//! the candidate commit, and runs every protected-file check on that real list.
//!
//! Rules, all fail closed:
//! - a path must be relative, non-empty, valid UTF-8, without `\`, NUL, `..`,
//!   or a `.git` component;
//! - a path must sit inside one of the declared roots;
//! - a changed entry must be a regular file (mode 100644 or 100755) on both
//!   sides; symlinks (120000) and submodules (160000) are refused;
//! - the real changed set must be exactly the declared target file;
//! - `RootOfTrust::validate_declared_files` and
//!   `SecurityLayer::evaluate_candidate` run on the real paths and real patch.
//!
//! There is no flag, tier, or environment variable that skips these checks.

use crate::evaluator::SecurityLayer;
use crate::isolation::RootOfTrust;
use std::path::Path;
use std::process::{Command, Stdio};

/// The tier the ratifier evaluates at. Root-of-trust files need tier 2; the
/// ratifier never grants it, so protected files always need a human change.
pub const RATIFIER_TIER: u8 = 1;

/// Roots a proposal may touch when the config does not say otherwise.
pub const DEFAULT_RATIFY_ROOTS: &[&str] = &["README.md", "CONTRIBUTING.md", "docs", "src"];

pub fn default_ratify_roots() -> Vec<String> {
    DEFAULT_RATIFY_ROOTS.iter().map(|s| s.to_string()).collect()
}

/// Normalizes a repository-relative path and refuses anything that could
/// point outside the repository or into git's own metadata.
pub fn normalize_repo_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty path".to_string());
    }
    if raw.contains('\0') {
        return Err(format!("path contains NUL: {:?}", raw));
    }
    if raw.contains('\\') {
        return Err(format!("path contains backslash: {:?}", raw));
    }
    if raw.starts_with('/') {
        return Err(format!("absolute path refused: {:?}", raw));
    }
    let mut parts: Vec<&str> = Vec::new();
    for comp in raw.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return Err(format!("parent-directory component refused: {:?}", raw)),
            c if c.eq_ignore_ascii_case(".git") => {
                return Err(format!("git metadata path refused: {:?}", raw))
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Err(format!("path names the repository root: {:?}", raw));
    }
    Ok(parts.join("/"))
}

/// True when `path` (already normalized) equals a root or sits below it,
/// compared whole component by whole component.
pub fn within_roots(path: &str, roots: &[String]) -> bool {
    let p: Vec<&str> = path.split('/').collect();
    roots.iter().any(|root| match normalize_repo_path(root) {
        Ok(r) => {
            let r: Vec<&str> = r.split('/').collect();
            p.len() >= r.len() && p[..r.len()] == r[..]
        }
        Err(_) => false,
    })
}

/// Checks a declared target before anything is staged or written.
pub fn check_declared_target(target_file: &str, roots: &[String]) -> Result<String, String> {
    let normalized = normalize_repo_path(target_file)?;
    if !within_roots(&normalized, roots) {
        return Err(format!(
            "target {:?} is outside the declared roots {:?}",
            normalized, roots
        ));
    }
    RootOfTrust::assert_patch_permitted(&normalized, RATIFIER_TIER)?;
    Ok(normalized)
}

/// One changed entry reported by `git diff-tree --raw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedEntry {
    pub old_mode: String,
    pub new_mode: String,
    pub status: char,
    pub path: String,
}

fn git(repo: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(repo);
    // A repo-local hook or config must not run code during ratification.
    c.args(["-c", "core.hooksPath=/dev/null"]);
    c
}

fn run(mut cmd: Command, what: &str) -> Result<String, String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {}", what, e))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed: {}",
            what,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Parses `git diff-tree -r -z --raw --no-renames` output.
pub fn parse_raw_diff(raw: &[u8]) -> Result<Vec<ChangedEntry>, String> {
    let mut entries = Vec::new();
    let mut fields = raw.split(|b| *b == 0).filter(|f| !f.is_empty());
    while let Some(meta) = fields.next() {
        let meta = std::str::from_utf8(meta).map_err(|_| "non-UTF-8 diff header".to_string())?;
        let meta = meta
            .strip_prefix(':')
            .ok_or_else(|| format!("unexpected diff header {:?}", meta))?;
        let cols: Vec<&str> = meta.split(' ').collect();
        if cols.len() != 5 {
            return Err(format!("unexpected diff header {:?}", meta));
        }
        let status = cols[4]
            .chars()
            .next()
            .ok_or_else(|| "empty diff status".to_string())?;
        let path = fields
            .next()
            .ok_or_else(|| "diff entry without a path".to_string())?;
        let path = std::str::from_utf8(path)
            .map_err(|_| "non-UTF-8 path in diff".to_string())?
            .to_string();
        entries.push(ChangedEntry {
            old_mode: cols[0].to_string(),
            new_mode: cols[1].to_string(),
            status,
            path,
        });
    }
    Ok(entries)
}

/// Asks git for the real changed entries between two commits.
pub fn real_diff(repo: &Path, base: &str, head: &str) -> Result<Vec<ChangedEntry>, String> {
    let out = git(repo)
        .args(["diff-tree", "-r", "-z", "--raw", "--no-renames", base, head])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git diff-tree: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "git diff-tree failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_raw_diff(&out.stdout)
}

/// Unified diff text of the real change, used for the content checks.
pub fn real_patch_text(repo: &Path, base: &str, head: &str) -> Result<String, String> {
    let mut c = git(repo);
    c.args([
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        base,
        head,
    ]);
    run(c, "git diff")
}

fn is_regular_mode(mode: &str) -> bool {
    mode == "100644" || mode == "100755"
}

/// Every check on the real diff. Returns the list of violations; empty means pass.
pub fn check_real_diff(
    entries: &[ChangedEntry],
    patch_text: &str,
    declared_target: &str,
    roots: &[String],
) -> Vec<String> {
    let mut violations = Vec::new();
    if entries.is_empty() {
        violations.push("real diff is empty; nothing to propose".to_string());
    }
    let mut real_paths = Vec::new();
    for e in entries {
        let normalized = match normalize_repo_path(&e.path) {
            Ok(p) => p,
            Err(err) => {
                violations.push(format!("real diff path refused: {}", err));
                continue;
            }
        };
        if normalized != e.path {
            violations.push(format!("real diff path is not canonical: {:?}", e.path));
        }
        if !within_roots(&normalized, roots) {
            violations.push(format!(
                "real diff touches {:?}, outside the declared roots {:?}",
                normalized, roots
            ));
        }
        let old_ok = e.old_mode == "000000" || is_regular_mode(&e.old_mode);
        let new_ok = e.new_mode == "000000" || is_regular_mode(&e.new_mode);
        if !old_ok || !new_ok {
            violations.push(format!(
                "real diff entry {:?} is not a regular file (mode {} -> {}); symlinks and submodules are refused",
                normalized, e.old_mode, e.new_mode
            ));
        }
        if e.new_mode == "000000" || e.status == 'D' {
            violations.push(format!(
                "real diff deletes {:?}; deletions are refused",
                normalized
            ));
        }
        real_paths.push(normalized);
    }
    if real_paths.len() != 1 || real_paths[0] != declared_target {
        violations.push(format!(
            "real diff paths {:?} differ from the declared target {:?}",
            real_paths, declared_target
        ));
    }
    if let Err(errs) = RootOfTrust::validate_declared_files(&real_paths, RATIFIER_TIER) {
        violations.extend(errs);
    }
    // Content checks look at what the change adds, not at unchanged context lines.
    let added: String = patch_text
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .map(|l| format!("{}\n", &l[1..]))
        .collect();
    let sec = SecurityLayer::evaluate_candidate(&real_paths, &added, RATIFIER_TIER);
    if !sec.passed {
        violations.extend(sec.violations);
    }
    violations
}

/// The candidate built off to the side.
#[derive(Debug, Clone)]
pub struct StagedCandidate {
    pub base: String,
    pub commit: String,
    pub entries: Vec<ChangedEntry>,
    pub patch_text: String,
}

/// Builds the candidate commit with a temporary index. Nothing in the working
/// tree, the real index, or any branch changes. The commit object is left
/// unreferenced until the caller decides to create a review branch.
pub fn stage_candidate_commit(
    repo: &Path,
    target_path: &str,
    contents: &[u8],
    author_name: &str,
    author_email: &str,
    message: &str,
) -> Result<StagedCandidate, String> {
    let mut c = git(repo);
    c.args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]);
    let base = run(c, "resolve base commit")?;
    if base.is_empty() {
        return Err("target repository has no base commit".to_string());
    }

    // Keep the existing executable bit; refuse a symlink or submodule target,
    // and refuse a target whose parent directory is a symlink in the base tree.
    let mut mode = "100644".to_string();
    let parts: Vec<&str> = target_path.split('/').collect();
    for i in 1..=parts.len() {
        let prefix = parts[..i].join("/");
        let mut c = git(repo);
        c.args(["ls-tree", "-z", &base, "--", &prefix]);
        let listing = run(c, "inspect base tree")?;
        if let Some(entry) = listing.split('\0').find(|l| !l.is_empty()) {
            let entry_mode = entry.split(' ').next().unwrap_or("");
            if entry_mode == "120000" || entry_mode == "160000" {
                return Err(format!(
                    "{:?} is a symlink or submodule in the base tree; refused",
                    prefix
                ));
            }
            if i == parts.len() && is_regular_mode(entry_mode) {
                mode = entry_mode.to_string();
            }
        }
    }

    let tmp = tempfile::tempdir().map_err(|e| format!("temp index dir: {}", e))?;
    let index = tmp.path().join("index");

    let mut c = git(repo);
    c.env("GIT_INDEX_FILE", &index).args(["read-tree", &base]);
    run(c, "read base tree into temporary index")?;

    let mut child = git(repo)
        .args(["hash-object", "-w", "--no-filters", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("git hash-object: {}", e))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or("hash-object stdin")?;
        stdin
            .write_all(contents)
            .map_err(|e| format!("write blob: {}", e))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("git hash-object: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let blob = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let mut c = git(repo);
    c.env("GIT_INDEX_FILE", &index).args([
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("{},{},{}", mode, blob, target_path),
    ]);
    run(c, "add blob to temporary index")?;

    let mut c = git(repo);
    c.env("GIT_INDEX_FILE", &index).args(["write-tree"]);
    let tree = run(c, "write candidate tree")?;

    let mut c = git(repo);
    c.env("GIT_AUTHOR_NAME", author_name)
        .env("GIT_AUTHOR_EMAIL", author_email)
        .env("GIT_COMMITTER_NAME", author_name)
        .env("GIT_COMMITTER_EMAIL", author_email)
        .args(["commit-tree", &tree, "-p", &base, "-m", message]);
    let commit = run(c, "create candidate commit")?;

    let entries = real_diff(repo, &base, &commit)?;
    let patch_text = real_patch_text(repo, &base, &commit)?;
    Ok(StagedCandidate {
        base,
        commit,
        entries,
        patch_text,
    })
}

/// Branch names the ratifier must never write to.
pub fn default_branch_names(repo: &Path) -> Vec<String> {
    let mut names = vec!["main".to_string(), "master".to_string()];
    let mut c = git(repo);
    c.args(["symbolic-ref", "--quiet", "--short", "HEAD"]);
    if let Ok(h) = run(c, "current branch") {
        if !h.is_empty() {
            names.push(h);
        }
    }
    let mut c = git(repo);
    c.args([
        "symbolic-ref",
        "--quiet",
        "--short",
        "refs/remotes/origin/HEAD",
    ]);
    if let Ok(h) = run(c, "origin default branch") {
        if let Some(b) = h.strip_prefix("origin/") {
            names.push(b.to_string());
        }
    }
    let mut c = git(repo);
    c.args(["config", "--get", "init.defaultBranch"]);
    if let Ok(h) = run(c, "init.defaultBranch") {
        if !h.is_empty() {
            names.push(h);
        }
    }
    names
}

/// Review branch name for a proposal id. Only `[A-Za-z0-9_-]` ids are accepted.
pub fn review_branch_name(proposal_id: &str) -> Result<String, String> {
    if proposal_id.is_empty()
        || proposal_id.len() > 100
        || !proposal_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "proposal id {:?} is not usable in a branch name",
            proposal_id
        ));
    }
    Ok(format!("rsi/{}", proposal_id))
}

/// Creates the review branch at `commit`. Refuses to touch a default branch,
/// and refuses to move a branch that already exists (create-only update).
pub fn create_review_branch(repo: &Path, branch: &str, commit: &str) -> Result<(), String> {
    let short = branch.trim_start_matches("refs/heads/");
    if default_branch_names(repo).iter().any(|d| d == short) {
        return Err(format!("refusing to write default branch {:?}", short));
    }
    let full = format!("refs/heads/{}", short);
    let mut c = git(repo);
    c.args(["check-ref-format", &full]);
    run(c, "check branch name")?;
    let mut c = git(repo);
    // Empty old value: the ref must not exist yet.
    c.args(["update-ref", "-m", "rsi: review branch", &full, commit, ""]);
    run(c, "create review branch")?;
    Ok(())
}

/// Mailbox-format patch of the review commit, ready for a PR or `git am`.
pub fn format_patch(repo: &Path, commit: &str) -> Result<String, String> {
    let mut c = git(repo);
    c.args(["format-patch", "-1", "--stdout", "--no-color", commit]);
    run(c, "format patch")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<String> {
        default_ratify_roots()
    }

    #[test]
    fn normalization_rejects_escape_forms() {
        assert_eq!(normalize_repo_path("./docs//a.md").unwrap(), "docs/a.md");
        assert!(normalize_repo_path("../x").is_err());
        assert!(normalize_repo_path("docs/../Cargo.toml").is_err());
        assert!(normalize_repo_path("/etc/passwd").is_err());
        assert!(normalize_repo_path("docs\\..\\Cargo.toml").is_err());
        assert!(normalize_repo_path(".git/hooks/pre-commit").is_err());
        assert!(normalize_repo_path("docs/.GIT/config").is_err());
        assert!(normalize_repo_path("docs/a\0b").is_err());
        assert!(normalize_repo_path("./").is_err());
        assert!(normalize_repo_path("").is_err());
    }

    #[test]
    fn roots_match_whole_components_only() {
        assert!(within_roots("docs/a.md", &roots()));
        assert!(within_roots("README.md", &roots()));
        assert!(!within_roots("docsx/a.md", &roots()));
        assert!(!within_roots("README.md.bak", &roots()));
        assert!(!within_roots("Cargo.toml", &roots()));
        assert!(!within_roots(".github/workflows/ci.yml", &roots()));
    }

    #[test]
    fn declared_target_check_refuses_protected_and_outside() {
        assert!(check_declared_target("README.md", &roots()).is_ok());
        assert!(check_declared_target("Cargo.toml", &roots()).is_err());
        assert!(check_declared_target("src/isolation/root_of_trust.rs", &roots()).is_err());
        assert!(check_declared_target("src/../Cargo.toml", &roots()).is_err());
        assert!(check_declared_target("scripts/run.sh", &roots()).is_err());
    }

    #[test]
    fn raw_diff_parser_reads_modes_and_paths() {
        let raw =
            b":100644 120000 aaaa bbbb T\0docs/link\0:000000 100644 0000 cccc A\0docs/new.md\0";
        let e = parse_raw_diff(raw).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].new_mode, "120000");
        assert_eq!(e[0].path, "docs/link");
        assert_eq!(e[1].status, 'A');
    }

    #[test]
    fn real_diff_check_catches_symlink_and_extra_files() {
        let link = vec![ChangedEntry {
            old_mode: "000000".into(),
            new_mode: "120000".into(),
            status: 'A',
            path: "docs/link".into(),
        }];
        assert!(!check_real_diff(&link, "", "docs/link", &roots()).is_empty());

        let extra = vec![
            ChangedEntry {
                old_mode: "100644".into(),
                new_mode: "100644".into(),
                status: 'M',
                path: "README.md".into(),
            },
            ChangedEntry {
                old_mode: "100644".into(),
                new_mode: "100644".into(),
                status: 'M',
                path: "Cargo.toml".into(),
            },
        ];
        let v = check_real_diff(&extra, "", "README.md", &roots());
        assert!(v.iter().any(|m| m.contains("Cargo.toml")));
    }

    #[test]
    fn real_diff_check_alone_refuses_protected_file() {
        // Even if the declared check were skipped and roots listed it.
        let roots = vec!["Cargo.toml".to_string()];
        let e = vec![ChangedEntry {
            old_mode: "100644".into(),
            new_mode: "100644".into(),
            status: 'M',
            path: "Cargo.toml".into(),
        }];
        let v = check_real_diff(&e, "", "Cargo.toml", &roots);
        assert!(v.iter().any(|m| m.contains("protected")), "{:?}", v);
    }

    #[test]
    fn real_diff_check_runs_root_of_trust_itself_not_only_via_security_layer() {
        // A protected file inside a default root ("src"). Both the gate's own
        // RootOfTrust call and the SecurityLayer must refuse it, independently.
        // The SecurityLayer wraps its finding as "Root-of-trust violation: ...";
        // the gate's direct call reports "SECURITY VIOLATION: ..." unwrapped.
        // Removing the direct RootOfTrust call in check_real_diff fails this test.
        let path = "src/isolation/container.rs";
        assert!(within_roots(path, &roots()));
        let e = vec![ChangedEntry {
            old_mode: "100644".into(),
            new_mode: "100644".into(),
            status: 'M',
            path: path.into(),
        }];
        let v = check_real_diff(&e, "", path, &roots());
        let direct: Vec<&String> = v
            .iter()
            .filter(|m| m.starts_with("SECURITY VIOLATION:") && m.contains(path))
            .collect();
        assert_eq!(
            direct.len(),
            1,
            "gate's own root-of-trust refusal missing: {:?}",
            v
        );
        assert!(
            v.iter()
                .any(|m| m.starts_with("Root-of-trust violation:") && m.contains(path)),
            "security layer refusal missing: {:?}",
            v
        );
    }

    #[test]
    fn branch_names_are_sanitized() {
        assert_eq!(review_branch_name("prop-abc").unwrap(), "rsi/prop-abc");
        assert!(review_branch_name("../main").is_err());
        assert!(review_branch_name("a b").is_err());
        assert!(review_branch_name("").is_err());
    }
}
