//! store_check — validate a backup directory without hardware: what
//! `BackupStore::exists_verified` will decide and, if it fails, the
//! exact reason. Run from the repository root:
//!
//!   cargo run -p jb-core --example store_check --release -- backup/<serial>

use jb_core::backup_store::BackupStore;
use std::path::Path;

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: store_check <backup-dir>");
        std::process::exit(2);
    };
    let dir = Path::new(&dir);
    match BackupStore::open(dir) {
        Err(e) => {
            println!("НЕВАЛИДЕН (open): {e}");
            std::process::exit(1);
        }
        Ok(store) => {
            println!("open: ок, разделов в карте: {}", store.parts().count());
            match store.verify() {
                Ok(()) => println!("ВАЛИДЕН: суммы полны и сходятся"),
                Err(e) => {
                    println!("НЕВАЛИДЕН (verify): {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
