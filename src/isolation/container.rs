use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct SandboxLimits {
    pub max_memory_mb: u64,
    pub max_cpu_percent: u32,
    pub max_pids: u32,
    pub timeout_seconds: u64,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 16384,
            max_cpu_percent: 800,
            max_pids: 256,
            timeout_seconds: 180,
        }
    }
}

impl SandboxLimits {
    pub fn new(max_memory_mb: u64, max_cpu_percent: u32, max_pids: u32, timeout_seconds: u64) -> Self {
        Self {
            max_memory_mb,
            max_cpu_percent,
            max_pids,
            timeout_seconds,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuildJail {
    pub builder_image: String,
    pub host_source_dir: PathBuf,
    pub host_output_dir: PathBuf,
    pub limits: SandboxLimits,
}

impl BuildJail {
    pub fn new(builder_image: &str, host_source: &Path, host_output: &Path) -> Self {
        Self {
            builder_image: builder_image.to_string(),
            host_source_dir: host_source.to_path_buf(),
            host_output_dir: host_output.to_path_buf(),
            limits: SandboxLimits::default(),
        }
    }

    pub fn build_docker_args(&self, command: &[&str]) -> Vec<String> {
        let uid = unsafe { libc::getuid() }.to_string();
        let gid = unsafe { libc::getgid() }.to_string();

        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--network".to_string(),
            "none".to_string(),
            "--read-only".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--memory".to_string(),
            format!("{}m", self.limits.max_memory_mb),
            "--cpus".to_string(),
            format!("{:.2}", self.limits.max_cpu_percent as f64 / 100.0),
            "--pids-limit".to_string(),
            self.limits.max_pids.to_string(),
            "-u".to_string(),
            format!("{}:{}", uid, gid),
            "-v".to_string(),
            format!("{}:/workspace/src:ro", self.host_source_dir.display()),
            "-v".to_string(),
            format!("{}:/output:rw", self.host_output_dir.display()),
            "--tmpfs".to_string(),
            "/tmp:rw,size=4G,mode=1777".to_string(),
            "--tmpfs".to_string(),
            "/build:rw,size=8G,mode=1777".to_string(),
            "-w".to_string(),
            "/build".to_string(),
            self.builder_image.clone(),
        ];

        for c in command {
            args.push(c.to_string());
        }

        args
    }

    pub fn execute(&self, command: &[&str]) -> Result<(bool, String, String), String> {
        let args = self.build_docker_args(command);
        let output = Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to invoke docker container: {}", e))?;

        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct GpuEvaluationJail {
    pub eval_image: String,
    pub host_artifact_dir: PathBuf,
    pub host_holdout_dir: PathBuf,
    pub cdi_device: String,
    pub limits: SandboxLimits,
}

impl GpuEvaluationJail {
    pub fn new(eval_image: &str, artifact_dir: &Path, holdout_dir: &Path) -> Self {
        Self {
            eval_image: eval_image.to_string(),
            host_artifact_dir: artifact_dir.to_path_buf(),
            host_holdout_dir: holdout_dir.to_path_buf(),
            cdi_device: "nvidia.com/gpu=0".to_string(),
            limits: SandboxLimits::new(49152, 800, 256, 300), // 48 GB limit, 300s timeout
        }
    }

    pub fn build_docker_args(&self, command: &[&str]) -> Vec<String> {
        let uid = unsafe { libc::getuid() }.to_string();
        let gid = unsafe { libc::getgid() }.to_string();

        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--device".to_string(),
            self.cdi_device.clone(),
            "--read-only".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--memory".to_string(),
            format!("{}m", self.limits.max_memory_mb),
            "--cpus".to_string(),
            format!("{:.2}", self.limits.max_cpu_percent as f64 / 100.0),
            "-u".to_string(),
            format!("{}:{}", uid, gid),
            "-v".to_string(),
            format!("{}:/artifacts:ro", self.host_artifact_dir.display()),
            "-v".to_string(),
            format!("{}:/holdouts:ro", self.host_holdout_dir.display()),
            "--tmpfs".to_string(),
            "/tmp:rw,size=4G,mode=1777".to_string(),
            "-w".to_string(),
            "/artifacts".to_string(),
            self.eval_image.clone(),
        ];

        for c in command {
            args.push(c.to_string());
        }

        args
    }

    pub fn execute(&self, command: &[&str]) -> Result<(bool, String, String), String> {
        let args = self.build_docker_args(command);
        let output = Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to invoke GPU evaluation container: {}", e))?;

        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_jail_args() {
        let jail = BuildJail::new(
            "spark-rsi-builder@sha256:123456",
            Path::new("/tmp/src"),
            Path::new("/tmp/out"),
        );
        let args = jail.build_docker_args(&["cargo", "build", "--offline"]);

        assert!(args.contains(&"--network".to_string()));
        assert!(args.contains(&"none".to_string()));
        assert!(args.contains(&"--read-only".to_string()));
        assert!(args.contains(&"--cap-drop".to_string()));
        assert!(args.contains(&"ALL".to_string()));
        assert!(args.contains(&"/tmp/src:/workspace/src:ro".to_string()));
        assert!(args.contains(&"/tmp/out:/output:rw".to_string()));
        assert!(args.contains(&"cargo".to_string()));
    }

    #[test]
    fn test_gpu_eval_jail_args() {
        let jail = GpuEvaluationJail::new(
            "spark-rsi-eval@sha256:abcdef",
            Path::new("/tmp/art"),
            Path::new("/var/lib/holdouts"),
        );
        let args = jail.build_docker_args(&["./bench_suite", "--iterations", "30"]);

        assert!(args.contains(&"--device".to_string()));
        assert!(args.contains(&"nvidia.com/gpu=0".to_string()));
        assert!(args.contains(&"/tmp/art:/artifacts:ro".to_string()));
        assert!(args.contains(&"/var/lib/holdouts:/holdouts:ro".to_string()));
        assert!(args.contains(&"30".to_string()));
    }
}
