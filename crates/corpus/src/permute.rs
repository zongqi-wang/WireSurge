/// Seeded visit-each-once permutation over `[0, n)` with no allocation.
///
/// A small Feistel network gives a bijection on `[0, 2^bits)`; values that land
/// outside `[0, n)` are re-walked (cycle-walking) until they fall in range, so
/// every index in `[0, n)` is produced exactly once as `i` ranges over `[0, n)`.
pub fn permute_index(i: u64, n: u64, seed: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    let half_bits = (64 - (n - 1).leading_zeros()).div_ceil(2).max(1);
    let mask = (1u64 << half_bits) - 1;
    let mut value = i % n;
    loop {
        value = feistel(value, half_bits, mask, seed);
        if value < n {
            return value;
        }
    }
}

fn feistel(input: u64, half_bits: u32, mask: u64, seed: u64) -> u64 {
    let mut left = (input >> half_bits) & mask;
    let mut right = input & mask;
    for round in 0..4u64 {
        let mixed = (round_function(right ^ seed.wrapping_mul(round + 1)) ^ round) & mask;
        let next = left ^ mixed;
        left = right;
        right = next;
    }
    (left << half_bits) | right
}

fn round_function(value: u64) -> u64 {
    let mut x = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn permutation_visits_each_index_once() {
        for n in [1u64, 2, 7, 16, 17, 1000, 1024] {
            let seen: HashSet<u64> = (0..n).map(|i| permute_index(i, n, 0xabc)).collect();
            assert_eq!(seen.len(), n as usize, "n={n} must visit every index once");
            assert!(seen.iter().all(|&v| v < n));
        }
    }

    #[test]
    fn different_seeds_differ() {
        let a: Vec<u64> = (0..1000).map(|i| permute_index(i, 1000, 1)).collect();
        let b: Vec<u64> = (0..1000).map(|i| permute_index(i, 1000, 2)).collect();
        assert_ne!(a, b);
    }
}
