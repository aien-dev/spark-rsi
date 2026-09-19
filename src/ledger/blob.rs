use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(rsi_root: &Path) -> Result<Self, String> {
        let root = rsi_root.join("blobs");
        fs::create_dir_all(&root).map_err(|e| format!("Failed to create blobs dir: {}", e))?;
        Ok(Self { root })
    }

    pub fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = format!("{:x}", hasher.finalize());

        let dest = self.root.join(&digest);
        if dest.exists() {
            return Ok(digest);
        }

        let tmp_file = self.root.join(format!(".tmp.{}", uuid::Uuid::new_v4().simple()));
        fs::write(&tmp_file, data).map_err(|e| format!("Failed to write tmp blob: {}", e))?;
        fs::rename(&tmp_file, &dest).map_err(|e| format!("Failed to atomic rename blob: {}", e))?;

        Ok(digest)
    }

    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>, String> {
        let dest = self.root.join(digest);
        if !dest.exists() {
            return Err(format!("Blob not found: {}", digest));
        }

        let data = fs::read(&dest).map_err(|e| format!("Failed to read blob: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed = format!("{:x}", hasher.finalize());
        if computed != digest {
            return Err(format!("Blob corrupted: expected={}, computed={}", digest, computed));
        }

        Ok(data)
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.root.join(digest).exists()
    }

    pub fn verify_blob(&self, digest: &str) -> bool {
        self.get_blob(digest).is_ok()
    }

    pub fn root_dir(&self) -> &Path {
        &self.root
    }
}
