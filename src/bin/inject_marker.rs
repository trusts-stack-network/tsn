// Test helper: inject `reorg_in_progress` metadata marker into a TSN data dir
// to validate the KF-X auto-wipe-removal path. Not for production use.
//
// Usage:
//   tsn-inject-marker <data-dir> [marker-value]
//   tsn-inject-marker <data-dir> --clear

use std::sync::Arc;
use tsn::storage::Database;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <data-dir> [marker | --clear]", args[0]);
        std::process::exit(2);
    }
    // The main `tsn` binary opens the chain DB at `{data_dir}/blockchain`,
    // so this helper must target the same subdirectory.
    let data_dir = &args[1];
    let path_str = format!("{}/blockchain", data_dir);
    let path = path_str.as_str();
    let val = if args.len() >= 3 && args[2] == "--clear" {
        ""
    } else if args.len() >= 3 {
        args[2].as_str()
    } else {
        "test_marker_29621:29709"
    };
    {
        let db = Database::open(path).expect("open db");
        let db = Arc::new(db);
        if val == "--fastsync-placeholder" || val == "--fastsync-placeholder-with-height" {
            // KF-Y test scenario: simulate "snapshot missing but fast-sync
            // placeholders exist" by setting fast_sync_base_height to a
            // non-zero value and removing any state snapshot. This drives
            // the open() path that previously auto-wiped the DB.
            db.set_metadata("fast_sync_base_height", "30600").expect("set base");
            db.set_metadata("fast_sync_commitment_offset", "100").expect("set offset");
            // Force get_height() to return Some by ensuring block_heights tree has an entry.
            // Use raw sled access. Insert a fake hash at height 0.
            let raw = db.sled_db();
            if let Ok(bh_tree) = raw.open_tree("block_heights") {
                let h: u64 = 0;
                let dummy_hash = [0xAAu8; 32];
                bh_tree.insert(&h.to_be_bytes(), &dummy_hash).ok();
            }
            // Wipe any saved state snapshot rows so the open() code can't
            // find one. Sled tree iter+remove.
            // Easier: use raw sled access via sled_db().
            let raw = db.sled_db();
            if let Ok(snap_tree) = raw.open_tree("state_snapshots") {
                let keys: Vec<_> = snap_tree.iter().keys().filter_map(|r| r.ok()).collect();
                for k in keys {
                    let _ = snap_tree.remove(k);
                }
            }
            db.flush().expect("flush");
            println!("Injected KF-Y scenario (fast_sync_base=30600, snapshots cleared) at {}", path);
        } else {
            db.set_metadata("reorg_in_progress", val).expect("set");
            db.flush().expect("flush");
            let read = db.get_metadata("reorg_in_progress").expect("get").unwrap_or_default();
            println!(
                "{} reorg_in_progress = '{}' at {} (verified read='{}')",
                if val.is_empty() { "Cleared" } else { "Injected" },
                val,
                path,
                read
            );
        }
    }
    // Drop forces sled close before exit
}
