//! Silent's data directory moves to Reckless's on the first start after the rename
//! (ws-plaude/silent#113): whole, in one rename, never over an existing Reckless
//! directory, and a failure leaves Silent's directory as it was.

use std::{fs, path::Path};

use reckless::config::{migrate_datadir, DatadirMigration};
use temp_dir::TempDir;

/// A Silent data directory with an account, a key, the app state, labels and plugin storage.
fn silent_datadir(root: &Path) -> std::path::PathBuf {
    let legacy = root.join(".silent");
    for (path, content) in [
        ("app.bip138", "sealed app state"),
        ("app.lock", ""),
        ("keys/0a1b2c3d.json", "key record"),
        ("sp/savings/config.json", "account config"),
        ("sp/savings/labels.jsonl", "labels"),
        ("plugins/feerate/private/tree.bip138", "plugin storage"),
    ] {
        let file = legacy.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, content).unwrap();
    }
    legacy
}

fn files(dir: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let name = path.strip_prefix(dir).unwrap().display().to_string();
                found.push((name, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn silent_data_moves_over_whole() {
    let root = TempDir::new().unwrap();
    let legacy = silent_datadir(root.path());
    let before = files(&legacy);
    let dir = root.path().join(".reckless");
    assert_eq!(migrate_datadir(&legacy, &dir), Ok(DatadirMigration::Moved));
    assert!(!legacy.exists(), "Silent's directory is moved, not copied");
    assert_eq!(files(&dir), before, "every file arrives with its content");
}

#[test]
fn an_existing_reckless_dir_is_never_overwritten() {
    let root = TempDir::new().unwrap();
    let legacy = silent_datadir(root.path());
    let dir = root.path().join(".reckless");
    fs::create_dir_all(dir.join("sp/other")).unwrap();
    fs::write(dir.join("sp/other/config.json"), "reckless account").unwrap();
    let silent = files(&legacy);
    let reckless = files(&dir);
    assert_eq!(
        migrate_datadir(&legacy, &dir),
        Ok(DatadirMigration::Present)
    );
    assert_eq!(files(&legacy), silent, "Silent's directory is left alone");
    assert_eq!(files(&dir), reckless, "Reckless's directory is left alone");
}

#[test]
fn a_fresh_start_creates_nothing() {
    let root = TempDir::new().unwrap();
    let legacy = root.path().join(".silent");
    let dir = root.path().join(".reckless");
    assert_eq!(migrate_datadir(&legacy, &dir), Ok(DatadirMigration::Fresh));
    assert!(!legacy.exists() && !dir.exists());
}

#[test]
fn a_failed_move_leaves_silent_usable() {
    let root = TempDir::new().unwrap();
    let legacy = silent_datadir(root.path());
    let before = files(&legacy);
    // The rename cannot land: the target's parent does not exist.
    let dir = root.path().join("missing/.reckless");
    let error = migrate_datadir(&legacy, &dir).unwrap_err();
    assert!(!error.is_empty());
    assert_eq!(
        files(&legacy),
        before,
        "Silent's directory keeps every file"
    );
    assert!(!dir.exists());
}

#[test]
fn a_running_silent_blocks_the_move() {
    let root = TempDir::new().unwrap();
    let legacy = silent_datadir(root.path());
    let before = files(&legacy);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(legacy.join("app.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&lock).unwrap();
    let dir = root.path().join(".reckless");
    let error = migrate_datadir(&legacy, &dir).unwrap_err();
    assert!(error.contains("in use"), "{error}");
    assert_eq!(files(&legacy), before);
    assert!(!dir.exists());
    drop(lock);
    assert_eq!(migrate_datadir(&legacy, &dir), Ok(DatadirMigration::Moved));
}
