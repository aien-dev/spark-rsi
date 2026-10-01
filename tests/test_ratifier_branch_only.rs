//! The ratifier must never commit to the target's default branch. It builds a
//! review branch and a PR-ready patch, and runs the protected-file checks on
//! the REAL git diff. Each test below is a bypass attempt or a realistic fault.

use spark_rsi::diff_gate::default_ratify_roots;
use spark_rsi::models::{ImprovementProposal, InvariantReport, ProposalKind};
use spark_rsi::Ratifier;
use std::path::Path;
use std::process::Command;

const DEAD_CORTEX: &str = "http://127.0.0.1:9";

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn git_ok(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A target repository on `main` with a README, a docs file, and a Cargo.toml.
fn make_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "user.email", "test@example.invalid"]);
    std::fs::write(repo.join("README.md"), "Fast \u{2014} and small.\n").unwrap();
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::write(repo.join("docs/guide.md"), "guide\n").unwrap();
    std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"t\"\n").unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", "initial"]);
    tmp
}

fn proposal(id: &str, target: &str, content: &str) -> ImprovementProposal {
    ImprovementProposal {
        id: id.to_string(),
        title: "test proposal".to_string(),
        description: "test".to_string(),
        target_file: target.to_string(),
        proposed_patch: content.to_string(),
        kind: ProposalKind::UnslopSanitization,
        created_at: "now".to_string(),
        sandbox_path: None,
        operator_signature: None,
    }
}

fn passed() -> InvariantReport {
    InvariantReport {
        passed: true,
        unslop_clean: true,
        em_dash_detected: 0,
        en_dash_detected: 0,
        forbidden_buzzwords_detected: vec![],
        antithesis_tropes_detected: vec![],
        zero_disk_secrets_clean: true,
        secret_leaks: vec![],
        compilation_passed: true,
        compilation_error: None,
        tests_passed: true,
        test_output_summary: None,
        notes: vec![],
    }
}

struct Snapshot {
    head: String,
    main: String,
    status: String,
    branches: String,
    readme: Vec<u8>,
}

fn snapshot(repo: &Path) -> Snapshot {
    Snapshot {
        head: git(repo, &["rev-parse", "HEAD"]),
        main: git(repo, &["rev-parse", "refs/heads/main"]),
        status: git(repo, &["status", "--porcelain", "--untracked-files=all"]),
        branches: git(repo, &["for-each-ref", "--format=%(refname) %(objectname)"]),
        readme: std::fs::read(repo.join("README.md")).unwrap_or_default(),
    }
}

fn assert_untouched(repo: &Path, before: &Snapshot) {
    let after = snapshot(repo);
    assert_eq!(before.head, after.head, "HEAD moved");
    assert_eq!(before.main, after.main, "default branch moved");
    assert_eq!(before.status, after.status, "working tree or index changed");
    assert_eq!(before.readme, after.readme, "working tree file changed");
}

async fn ratify(
    repo: &Path,
    patch_dir: &Path,
    p: &ImprovementProposal,
    roots: &[String],
) -> spark_rsi::models::RatificationRecord {
    Ratifier::ratify_proposal(
        p,
        &passed(),
        repo,
        roots,
        patch_dir,
        Some("ledger-hash"),
        DEAD_CORTEX,
        "test",
    )
    .await
    .expect("ratifier returns a record")
}

#[tokio::test]
async fn ratifier_makes_review_branch_and_patch_never_default_branch() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);

    let p = proposal("prop-good1", "README.md", "Fast, and small.\n");
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;

    assert_eq!(rec.status, "ProposedForReview", "{}", rec.message);
    assert_untouched(repo, &before);

    let branch = rec.branch.clone().unwrap();
    assert_eq!(branch, "rsi/prop-good1");
    let tip = git(repo, &["rev-parse", &format!("refs/heads/{}", branch)]);
    assert_eq!(Some(tip.clone()), rec.commit_hash);
    assert_eq!(git(repo, &["rev-parse", &format!("{}^", tip)]), before.main);
    assert_eq!(
        git(repo, &["diff", "--name-only", "main", &tip]),
        "README.md"
    );

    let patch = std::fs::read_to_string(rec.patch_path.unwrap()).unwrap();
    assert!(patch.contains("Subject: [PATCH] rsi: test proposal (prop-good1)"));
    assert!(patch.contains("+Fast, and small."));
    // The patch applies cleanly to the untouched default branch.
    let check = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(check.path(), &patch).unwrap();
    assert!(git_ok(
        repo,
        &["apply", "--check", check.path().to_str().unwrap()]
    ));
}

#[tokio::test]
async fn dotdot_target_cannot_reach_protected_file() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    for target in [
        "docs/../Cargo.toml",
        "../outside.txt",
        "/etc/passwd",
        "docs\\..\\Cargo.toml",
        ".git/hooks/post-commit",
        "docs/./../.git/config",
    ] {
        let p = proposal("prop-dotdot", target, "pwned\n");
        let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
        assert_eq!(rec.status, "Rejected", "target {:?} was accepted", target);
        assert!(rec.branch.is_none());
    }
    assert_untouched(repo, &before);
    assert_eq!(before.branches, snapshot(repo).branches, "a branch was created");
}

#[tokio::test]
async fn protected_file_refused_even_when_listed_as_root() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    // A misconfigured root list cannot open a root-of-trust file.
    let roots = vec!["Cargo.toml".to_string(), ".github".to_string()];
    for target in ["Cargo.toml", ".github/workflows/ci.yml"] {
        let p = proposal("prop-prot", target, "[package]\nname = \"evil\"\n");
        let rec = ratify(repo, patches.path(), &p, &roots).await;
        assert_eq!(rec.status, "Rejected", "{}", target);
        assert!(rec.message.contains("protected"), "{}", rec.message);
    }
    assert_untouched(repo, &before);
}

#[tokio::test]
async fn target_outside_declared_roots_refused() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    for target in ["scripts/install.sh", "docsx/a.md", "README.md.orig"] {
        let p = proposal("prop-out", target, "echo hi\n");
        let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
        assert_eq!(rec.status, "Rejected", "{}", target);
        assert!(rec.message.contains("outside the declared roots"), "{}", rec.message);
    }
    assert_untouched(repo, &before);
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_in_base_tree_refused() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    // docs/link -> ../Cargo.toml, and docs/sub -> ../.github (symlinked directory)
    std::os::unix::fs::symlink("../Cargo.toml", repo.join("docs/link")).unwrap();
    std::fs::create_dir_all(repo.join(".github/workflows")).unwrap();
    std::fs::write(repo.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    std::os::unix::fs::symlink("../.github", repo.join("docs/sub")).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", "links"]);
    let before = snapshot(repo);

    for target in ["docs/link", "docs/sub/workflows/ci.yml"] {
        let p = proposal("prop-link", target, "evil\n");
        let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
        assert_eq!(rec.status, "Rejected", "{}", target);
        assert!(rec.message.contains("symlink"), "{}", rec.message);
    }
    assert_untouched(repo, &before);
    assert_eq!(
        std::fs::read_to_string(repo.join("Cargo.toml")).unwrap(),
        "[package]\nname = \"t\"\n"
    );
}

#[tokio::test]
async fn secret_in_real_diff_refused() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    let key = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
    let p = proposal("prop-secret", "docs/guide.md", &format!("guide\nkey={}\n", key));
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
    assert_eq!(rec.status, "Rejected");
    assert!(rec.message.contains("secret"), "{}", rec.message);
    assert_untouched(repo, &before);
}

#[tokio::test]
async fn network_primitive_in_real_diff_refused() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let p = proposal(
        "prop-net",
        "src/lib.rs",
        "pub fn f() { let _ = std::net::TcpStream::connect(\"1.2.3.4:80\"); }\n",
    );
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
    assert_eq!(rec.status, "Rejected");
    assert!(rec.message.contains("network"), "{}", rec.message);
}

#[tokio::test]
async fn unchanged_content_is_not_a_proposal() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let p = proposal("prop-same", "docs/guide.md", "guide\n");
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
    assert_eq!(rec.status, "Rejected");
    assert!(rec.message.contains("empty"), "{}", rec.message);
}

#[tokio::test]
async fn current_branch_named_like_review_branch_is_never_written() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    // The checked-out (default) branch has the review branch's name.
    git(repo, &["checkout", "-q", "-b", "rsi/prop-clash"]);
    let tip = git(repo, &["rev-parse", "HEAD"]);
    let p = proposal("prop-clash", "README.md", "changed\n");
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
    assert_eq!(rec.status, "Rejected", "{}", rec.message);
    assert!(rec.message.contains("default branch"), "{}", rec.message);
    assert_eq!(git(repo, &["rev-parse", "refs/heads/rsi/prop-clash"]), tip);
}

#[tokio::test]
async fn existing_review_branch_is_not_moved() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let main = git(repo, &["rev-parse", "main"]);
    git(repo, &["branch", "rsi/prop-dup", &main]);
    let p = proposal("prop-dup", "README.md", "changed\n");
    let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
    assert_eq!(rec.status, "Rejected", "{}", rec.message);
    assert_eq!(git(repo, &["rev-parse", "refs/heads/rsi/prop-dup"]), main);
}

#[tokio::test]
async fn hostile_proposal_id_cannot_name_a_branch() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    for id in ["../main", "x/../../main", "a b", ""] {
        let p = proposal(id, "README.md", "changed\n");
        let rec = ratify(repo, patches.path(), &p, &default_ratify_roots()).await;
        assert_eq!(rec.status, "Rejected", "id {:?}", id);
    }
    assert_untouched(repo, &before);
    assert_eq!(before.branches, snapshot(repo).branches);
}

#[tokio::test]
async fn failed_invariants_never_touch_git() {
    let tmp = make_repo();
    let repo = tmp.path();
    let patches = tempfile::tempdir().unwrap();
    let before = snapshot(repo);
    let mut inv = passed();
    inv.passed = false;
    let p = proposal("prop-inv", "README.md", "changed\n");
    let rec = Ratifier::ratify_proposal(
        &p,
        &inv,
        repo,
        &default_ratify_roots(),
        patches.path(),
        None,
        DEAD_CORTEX,
        "test",
    )
    .await
    .unwrap();
    assert_eq!(rec.status, "Rejected");
    assert_untouched(repo, &before);
    assert_eq!(before.branches, snapshot(repo).branches);
}
