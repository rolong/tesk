use std::path::{Path, PathBuf};

use parking_lot::Mutex;

extern crate common_types as types;
extern crate ethereum_types;

mod noncegen_rust;
mod poc_hashing;
mod shabal256;
//#[cfg(feature = "bench")]
//pub mod compute;
//#[cfg(not(feature = "bench"))]
pub mod compute;

pub use noncegen_rust::*;
pub use poc_hashing::*;
pub use shabal256::*;

struct LightCache {
    recent_epoch: Option<u64>,
    prev_epoch: Option<u64>,
}

/// Light/Full cache manager.
pub struct SkhashManager {
    cache: Mutex<LightCache>,
    cache_dir: PathBuf,
}

impl SkhashManager {
    /// Create a new instance of skhash manager
    pub fn new(cache_dir: &Path) -> SkhashManager {
        SkhashManager {
            cache_dir: cache_dir.to_path_buf(),
            cache: Mutex::new(LightCache {
                recent_epoch: None,
                prev_epoch: None,
            }),
        }
    }
}
