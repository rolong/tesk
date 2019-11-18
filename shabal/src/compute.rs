use std::mem::transmute;
use std::u64;

use crate::shabal256::{shabal256_deadline_fast, shabal256_hash_fast};
use ethereum_types::H256;
use hex;

const HASH_SIZE: usize = 32;
const HASH_CAP: usize = 4096;
const NUM_SCOOPS: usize = 4096;
const SCOOP_SIZE: usize = 64;
const MESSAGE_SIZE: usize = 16;

pub const NONCE_SIZE: usize = (NUM_SCOOPS * SCOOP_SIZE);

/// Computation result
pub struct ProofOfCapacity {
    /// Difficulty boundary
    pub value: H256,
    /// Mix
    pub mix_hash: H256,
}

pub fn calculate_new_gensig(address: u64, gensig: &[u8; 32]) -> [u8; 32] {
    let mut data: [u8; 64] = [0; 64];
    let address_bytes: [u8; 8] = unsafe { transmute(address.to_be()) };

    data[..32].clone_from_slice(gensig);
    data[32..40].clone_from_slice(&address_bytes);
    data[40] = 0x80;

    let data = unsafe { transmute::<&[u8; 64], &[u32; 16]>(&data) };
    shabal256_hash_fast(&[], &data)
}

#[cfg(test)]
mod tests {
    use crate::{calculate_scoop, decode_gensig, find_best_deadline_rust};

    #[test]
    fn test_decode_gensig() {
        let gen_sig = "0000000000000000000000000000000000000000000000000000000000000000";
        let sig: [u8; 32] = [0u8; 32];
        let mut new_sig = decode_gensig(gen_sig);
        assert_eq!(new_sig, sig);
    }

    #[test]
    fn test_deadline_hashing() {
        let mut deadline: u64;
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();

        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        let winner: [u8; 64] = [0; 64];
        let loser: [u8; 64] = [5; 64];
        let mut data: [u8; 64 * 32] = [5; 64 * 32];

        for i in 0..32 {
            data[i * 64..i * 64 + 64].clone_from_slice(&winner);

            let result = find_best_deadline_rust(&data, (i + 1) as u64, &gensig_array);
            deadline = result.0;

            assert_eq!(3084580316385335914u64, deadline);
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }

}
