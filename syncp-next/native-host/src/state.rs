use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"SynCP Next isolated architecture proof v1\n";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub theme: Theme,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    api_version: u32,
    generation: u64,
    preferences: Preferences,
}

pub struct Store {
    root: PathBuf,
    _lock: File,
    pub preferences: Preferences,
    pub generation: u64,
    pub interrupted_staging_files: usize,
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_options().open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl Store {
    pub fn open(root: &Path) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(io::Error::other("Use an absolute isolated data directory"));
        }
        // The proof cannot adopt an existing application's directory.
        let created = !root.exists();
        if created {
            fs::create_dir_all(root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            }
        }
        if fs::symlink_metadata(root)?.file_type().is_symlink() {
            return Err(io::Error::other("A symlink cannot be the proof data root"));
        }
        let marker = root.join(".syncp-next-proof");
        if !marker.exists() {
            if fs::read_dir(root)?.next().is_some() {
                return Err(io::Error::other("Existing unowned directory is not accepted"));
            }
            write_new_private(&marker, MARKER)?;
        }
        if fs::read(&marker)? != MARKER {
            return Err(io::Error::other("Invalid ownership marker"));
        }
        let lock_path = root.join("host.lock");
        if lock_path.exists() && fs::symlink_metadata(&lock_path)?.file_type().is_symlink() {
            return Err(io::Error::other("Invalid lock file"));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock_exclusive()?;
        let mut generations = Vec::new();
        let mut interrupted_staging_files = 0;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("preferences-") && name.ends_with(".pending") {
                interrupted_staging_files += 1;
            }
            if let Some(number) = name.strip_prefix("preferences-").and_then(|s| s.strip_suffix(".json")) {
                let number = number.parse::<u64>().map_err(|_| io::Error::other("Invalid generation name"))?;
                generations.push((number, entry.path()));
            }
        }
        generations.sort_by_key(|entry| entry.0);
        let (generation, preferences) = if let Some((number, path)) = generations.last() {
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(io::Error::other("Invalid generation file"));
            }
            let mut bytes = Vec::new();
            File::open(path)?.take(8193).read_to_end(&mut bytes)?;
            if bytes.len() > 8192 {
                return Err(io::Error::other("Oversized generation"));
            }
            let saved: Generation = serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::other("Committed configuration is corrupt; recovery is required"))?;
            if saved.api_version != 1 || saved.generation != *number {
                return Err(io::Error::other("Unsupported or inconsistent configuration generation"));
            }
            (*number, saved.preferences)
        } else {
            (0, Preferences::default())
        };
        Ok(Self { root: root.to_owned(), _lock: lock, preferences, generation, interrupted_staging_files })
    }

    pub fn save(&mut self, preferences: Preferences) -> io::Result<()> {
        if self.interrupted_staging_files > 0 {
            return Err(io::Error::other("Interrupted staging requires a reviewed recovery operation"));
        }
        let next = self.generation.checked_add(1).ok_or_else(|| io::Error::other("Generation overflow"))?;
        let saved = Generation { api_version: 1, generation: next, preferences: preferences.clone() };
        let staged = self.root.join(format!("preferences-{next:020}.pending"));
        let committed = self.root.join(format!("preferences-{next:020}.json"));
        // No replacement rename is needed on Windows: each committed generation is immutable.
        write_new_private(&staged, &serde_json::to_vec(&saved)?)?;
        fs::rename(&staged, &committed)?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        self.generation = next;
        self.preferences = preferences;
        Ok(())
    }

    pub fn journal(&self, event: &'static str) -> io::Result<()> {
        let path = self.root.join("events.jsonl");
        if path.exists() && fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(io::Error::other("Invalid journal file"));
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?.as_secs();
        // Only source-defined event names: request bodies, credentials and commands never enter the journal.
        writeln!(file, "{}", serde_json::json!({"api_version":1,"at_unix":at,"event":event,"generation":self.generation}))?;
        file.sync_all()
    }
}

impl Store {
    pub fn root(&self) -> &Path { &self.root }

    pub fn observe_staging(&mut self) -> io::Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(&self.root)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with("preferences-") && name.ends_with(".pending") { count += 1; }
        }
        self.interrupted_staging_files = count;
        Ok(())
    }


    fn pending_inventory(&self) -> io::Result<Vec<serde_json::Value>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("preferences-") || !name.ends_with(".pending") { continue; }
            let number = name.strip_prefix("preferences-").and_then(|s|s.strip_suffix(".pending"))
                .ok_or_else(||io::Error::other("INVALID_STAGING_NAME"))?;
            if number.len() != 20 || !number.bytes().all(|b|b.is_ascii_digit()) {
                return Err(io::Error::other("INVALID_STAGING_NAME"));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
                return Err(io::Error::other("UNSAFE_STAGING_RECORD"));
            }
            files.push(serde_json::json!({"name":name,"bytes":metadata.len(),"sha256":crate::discovery::sha256(&entry.path())?}));
            if files.len() > 256 { return Err(io::Error::other("TOO_MANY_STAGING_RECORDS")); }
        }
        files.sort_by(|a,b|a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(files)
    }

    pub fn recovery_plan(&self) -> io::Result<serde_json::Value> {
        use sha2::{Digest, Sha256};
        let files = self.pending_inventory()?;
        let identity = serde_json::json!({"generation":self.generation,"files":files});
        let plan_id = format!("{:x}", Sha256::digest(serde_json::to_vec(&identity)?));
        Ok(serde_json::json!({"api_version":1,"ok":true,"plan_id":plan_id,"operation":"quarantine_interrupted_preferences",
            "observation":{"pending_records":files,"committed_generation":self.generation},
            "probable_cause":"An uncommitted write may have been interrupted; the exact cause is not established",
            "confidence":"observed pending files; cause uncertain","intervention":"Move only these uncommitted preference files to a new owned quarantine; preserve committed settings",
            "required_permission":"explicit manage-capability approval of this exact plan","destructive":false,
            "verification":"No pending records remain; the committed settings and generation are unchanged","executable":!files.is_empty()}))
    }

    pub fn approve_recovery(&mut self, plan_id: &str) -> io::Result<()> {
        let plan = self.recovery_plan()?;
        if plan["plan_id"].as_str() != Some(plan_id) || plan["executable"] != true {
            return Err(io::Error::other("STALE_OR_EMPTY_RECOVERY_PLAN"));
        }
        let files = self.pending_inventory()?;
        let quarantine = self.root.join(format!("quarantine-{}", crate::auth::token().map_err(|_|io::Error::other("RANDOM_SOURCE_FAILED"))?));
        fs::create_dir(&quarantine)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700))?;
        }
        self.journal("recovery.requested")?;
        for record in files {
            let name = record["name"].as_str().ok_or_else(||io::Error::other("INVALID_PLAN_RECORD"))?;
            // The approved inventory is bounded and source-validated; no arbitrary path is accepted.
            let path = self.root.join(name);
            if fs::symlink_metadata(&path)?.file_type().is_symlink()
                || crate::discovery::sha256(&path)? != record["sha256"].as_str().unwrap_or("") {
                return Err(io::Error::other("STAGING_CHANGED_AFTER_APPROVAL"));
            }
            fs::rename(path, quarantine.join(name))?;
        }
        self.interrupted_staging_files = self.pending_inventory()?.len();
        if self.interrupted_staging_files != 0 { return Err(io::Error::other("RECOVERY_VERIFICATION_FAILED")); }
        self.journal("recovery.verified")
    }

    pub fn events(&self) -> io::Result<serde_json::Value> {
        use std::io::{Seek, SeekFrom};
        let path = self.root.join("events.jsonl");
        if fs::symlink_metadata(&path)?.file_type().is_symlink() { return Err(io::Error::other("INVALID_JOURNAL")); }
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let skip_partial = size > 65536;
        if skip_partial { file.seek(SeekFrom::End(-65536))?; }
        let mut text = String::new(); file.take(65536).read_to_string(&mut text)?;
        let mut lines = text.lines(); if skip_partial { lines.next(); }
        let mut events = Vec::new();
        let mut malformed_records = 0;
        for line in lines {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => events.push(value),
                Err(_) => malformed_records += 1,
            }
        }
        Ok(serde_json::json!({"api_version":1,"ok":true,"events":events,"malformed_records":malformed_records,"bounded_tail_bytes":65536}))
    }
}
