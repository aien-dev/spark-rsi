use spark_rsi::actor::judge::HoldoutSuite;
use std::path::Path;

fn main() {
    let holdouts = Path::new(".rsi/holdouts");
    std::fs::create_dir_all(holdouts).unwrap();
    let suites = HoldoutSuite::builtin_suites();
    for s in &suites {
        s.save_to_dir(holdouts).unwrap();
    }
    println!(
        "Populated .rsi/holdouts with {} builtin holdout suites",
        suites.len()
    );
}
