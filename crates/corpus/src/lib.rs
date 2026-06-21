use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use wiresurge_core::{Result, WireSurgeError};

mod permute;
pub use permute::permute_index;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectMode {
    Sequential,
    RandomReplace,
    RandomPermute,
}

enum Backing {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Mapped(map) => map,
            Backing::Owned(buffer) => buffer,
        }
    }
}

/// An immutable corpus of query names, stored once and shared by reference.
///
/// Rows are byte ranges into the backing buffer; workers hold only an `Arc` and
/// an index, never copies of the names. Built before the run clock starts so a
/// large file cannot delay the first send (the flame large-file pitfall).
pub struct Corpus {
    backing: Backing,
    rows: Vec<(u32, u32)>,
}

impl Corpus {
    pub fn load(path: &Path) -> Result<Arc<Corpus>> {
        let file = std::fs::File::open(path).map_err(|error| {
            WireSurgeError::new("corpus_open_failed", error.to_string()).at("file")
        })?;
        let map = unsafe { Mmap::map(&file) }.map_err(|error| {
            WireSurgeError::new("corpus_map_failed", error.to_string()).at("file")
        })?;
        let rows = index_rows(&map);
        if rows.is_empty() {
            return Err(
                WireSurgeError::new("corpus_empty", "corpus file has no query rows").at("file"),
            );
        }
        Ok(Arc::new(Corpus {
            backing: Backing::Mapped(map),
            rows,
        }))
    }

    pub fn single(name: &str) -> Arc<Corpus> {
        let bytes = name.as_bytes().to_vec();
        let rows = vec![(0u32, bytes.len() as u32)];
        Arc::new(Corpus {
            backing: Backing::Owned(bytes),
            rows,
        })
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn row(&self, index: usize) -> &str {
        let (start, end) = self.rows[index];
        std::str::from_utf8(&self.backing.bytes()[start as usize..end as usize]).unwrap_or("")
    }

    /// Iterate over every row name in order. Used to encode the corpus once
    /// before a run starts.
    pub fn iter_rows(&self) -> impl Iterator<Item = &str> {
        (0..self.rows.len()).map(|index| self.row(index))
    }

    /// Map a query index to the corpus row it selects under `mode`, without
    /// dereferencing to the name. Callers that hold a precomputed per-row table
    /// (e.g. prebuilt wire messages) index into it with this instead of `select`.
    pub fn select_index(&self, idx: u64, seed: u64, mode: SelectMode) -> usize {
        let n = self.rows.len() as u64;
        let row = match mode {
            SelectMode::Sequential => idx % n,
            SelectMode::RandomReplace => splitmix64(idx ^ seed) % n,
            SelectMode::RandomPermute => permute_index(idx, n, seed),
        };
        row as usize
    }

    pub fn select(&self, idx: u64, seed: u64, mode: SelectMode) -> &str {
        self.row(self.select_index(idx, seed, mode))
    }
}

fn index_rows(bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut rows = Vec::new();
    let mut start = 0usize;
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            push_row(&mut rows, bytes, start, offset);
            start = offset + 1;
        }
    }
    push_row(&mut rows, bytes, start, bytes.len());
    rows
}

fn push_row(rows: &mut Vec<(u32, u32)>, bytes: &[u8], start: usize, mut end: usize) {
    if end > start && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    if end > start {
        rows.push((start as u32, end as u32));
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_corpus(lines: &[&str]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wiresurge-corpus-{}-{}.txt",
            std::process::id(),
            lines.len()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        path
    }

    #[test]
    fn single_name_corpus() {
        let corpus = Corpus::single("example.com");
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.row(0), "example.com");
        assert_eq!(corpus.select(7, 0, SelectMode::Sequential), "example.com");
    }

    #[test]
    fn loads_file_and_skips_blank_and_crlf() {
        let path = temp_corpus(&["a.com", "b.com", "", "c.com\r"]);
        let corpus = Corpus::load(&path).unwrap();
        assert_eq!(corpus.len(), 3);
        assert_eq!(corpus.row(0), "a.com");
        assert_eq!(corpus.row(2), "c.com");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sequential_wraps() {
        let path = temp_corpus(&["a", "b", "c"]);
        let corpus = Corpus::load(&path).unwrap();
        assert_eq!(corpus.select(0, 0, SelectMode::Sequential), "a");
        assert_eq!(corpus.select(3, 0, SelectMode::Sequential), "a");
        assert_eq!(corpus.select(4, 0, SelectMode::Sequential), "b");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn permute_mode_visits_each_row_once() {
        let path = temp_corpus(&["a", "b", "c", "d", "e"]);
        let corpus = Corpus::load(&path).unwrap();
        let mut seen = std::collections::HashSet::new();
        for idx in 0..corpus.len() as u64 {
            seen.insert(
                corpus
                    .select(idx, 99, SelectMode::RandomPermute)
                    .to_string(),
            );
        }
        assert_eq!(seen.len(), 5);
        let _ = std::fs::remove_file(path);
    }
}
