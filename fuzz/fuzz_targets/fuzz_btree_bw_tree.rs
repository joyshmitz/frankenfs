#![no_main]

use ffs_btree::bw_tree::{chain_length, BwKey, BwValue, ConsolidationConfig, MappingTable, PageId};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_PAGES: u8 = 16;
const KEY_DOMAIN: u64 = 256;
const MAX_VERIFY_PAGES: usize = 16;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> bool {
        self.pos < self.data.len()
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn page_index(&mut self, allocated: usize) -> Option<usize> {
        if allocated == 0 {
            return None;
        }
        Some(usize::from(self.next_u8()) % allocated)
    }

    fn key(&mut self) -> BwKey {
        BwKey(u64::from(self.next_u16()) % KEY_DOMAIN)
    }

    fn value(&mut self) -> BwValue {
        BwValue(u64::from(self.next_u32()))
    }

    fn threshold(&mut self) -> usize {
        usize::from(self.next_u8() % 12)
    }

    fn config(&mut self) -> ConsolidationConfig {
        ConsolidationConfig {
            chain_threshold: self.threshold(),
            max_retries: usize::from((self.next_u8() % 8).saturating_add(1)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PageModel {
    entries: BTreeMap<BwKey, BwValue>,
    chain_len: usize,
}

impl PageModel {
    fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            chain_len: 1,
        }
    }
}

fn fail() -> ! {
    std::process::abort();
}

fn require(condition: bool) {
    if !condition {
        fail();
    }
}

fn page_id(index: usize) -> PageId {
    PageId(match u64::try_from(index) {
        Ok(value) => value,
        Err(_) => fail(),
    })
}

fn invalid_page_id(allocated: usize, cursor: &mut ByteCursor<'_>) -> PageId {
    let allocated = match u64::try_from(allocated) {
        Ok(value) => value,
        Err(_) => u64::MAX.saturating_sub(8),
    };
    PageId(
        allocated
            .saturating_add(1)
            .saturating_add(u64::from(cursor.next_u8() % 8)),
    )
}

fn allocate_page(table: &MappingTable, models: &mut Vec<PageModel>) {
    match table.allocate_page() {
        Ok(id) => {
            let expected = page_id(models.len());
            require(id == expected);
            models.push(PageModel::empty());
        }
        Err(_) => {
            require(models.len() >= table.page_capacity());
        }
    }
}

fn insert_page(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let key = cursor.key();
    let value = cursor.value();
    require(table.insert(page_id(index), key, value).is_ok());
    models[index].entries.insert(key, value);
    models[index].chain_len = models[index].chain_len.saturating_add(1);
}

fn delete_page(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let key = cursor.key();
    require(table.delete(page_id(index), key).is_ok());
    models[index].entries.remove(&key);
    models[index].chain_len = models[index].chain_len.saturating_add(1);
}

fn split_page(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let separator = cursor.key();
    let sibling = if models.is_empty() {
        invalid_page_id(models.len(), cursor)
    } else {
        page_id(usize::from(cursor.next_u8()) % models.len())
    };
    require(
        table
            .append_split_delta(page_id(index), separator, sibling)
            .is_ok(),
    );
    let removed: Vec<_> = models[index]
        .entries
        .range(separator..)
        .map(|(key, _)| *key)
        .collect();
    for key in removed {
        models[index].entries.remove(&key);
    }
    models[index].chain_len = models[index].chain_len.saturating_add(1);
}

fn merge_page(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let sibling = if models.is_empty() {
        invalid_page_id(models.len(), cursor)
    } else {
        page_id(usize::from(cursor.next_u8()) % models.len())
    };
    require(table.append_merge_delta(page_id(index), sibling).is_ok());
    models[index].chain_len = models[index].chain_len.saturating_add(1);
}

fn consolidate_page(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let config = cursor.config();
    let before = models[index].chain_len;
    let entries_count = models[index].entries.len();
    let result = match table.consolidate_page(page_id(index), &config) {
        Ok(result) => result,
        Err(_) => fail(),
    };
    require(result.chain_len_before == before);
    if before <= 1 {
        require(result.chain_len_after == before);
        require(result.entries_count == 0);
        require(result.cas_attempts == 0);
    } else {
        require(result.chain_len_after == 1);
        require(result.entries_count == entries_count);
        require(result.cas_attempts >= 1);
        models[index].chain_len = 1;
    }
}

fn consolidate_all(table: &MappingTable, models: &mut [PageModel], cursor: &mut ByteCursor<'_>) {
    let config = cursor.config();
    let expected = models
        .iter()
        .filter(|model| model.chain_len > config.chain_threshold)
        .count();
    let actual = match table.consolidate_all(&config) {
        Ok(count) => count,
        Err(_) => fail(),
    };
    require(actual == expected);
    for model in models {
        if model.chain_len > config.chain_threshold {
            model.chain_len = 1;
        }
    }
}

fn check_lookup(table: &MappingTable, models: &[PageModel], cursor: &mut ByteCursor<'_>) {
    let Some(index) = cursor.page_index(models.len()) else {
        return;
    };
    let key = cursor.key();
    let expected = models[index].entries.get(&key).copied();
    let actual = match table.lookup(page_id(index), key) {
        Ok(value) => value,
        Err(_) => fail(),
    };
    require(actual == expected);
}

fn check_invalid_page(table: &MappingTable, models: &[PageModel], cursor: &mut ByteCursor<'_>) {
    let invalid = invalid_page_id(models.len(), cursor);
    require(table.get_page(invalid).is_err());
    require(table.lookup(invalid, cursor.key()).is_err());
    require(table.materialize_page(invalid).is_err());
}

fn check_scan(table: &MappingTable, models: &[PageModel], cursor: &mut ByteCursor<'_>) {
    let threshold = cursor.threshold();
    let expected: Vec<_> = models
        .iter()
        .enumerate()
        .filter_map(|(index, model)| {
            if model.chain_len > threshold {
                Some(page_id(index))
            } else {
                None
            }
        })
        .collect();
    require(table.scan_for_consolidation(threshold) == expected);
}

fn verify_pages(table: &MappingTable, models: &[PageModel]) {
    require(models.len() <= MAX_VERIFY_PAGES);
    for (index, model) in models.iter().enumerate() {
        let id = page_id(index);
        let state = match table.materialize_page(id) {
            Ok(state) => state,
            Err(_) => fail(),
        };
        require(state == model.entries);

        let snapshot = match table.get_page(id) {
            Ok(snapshot) => snapshot,
            Err(_) => fail(),
        };
        require(chain_length(&snapshot.head) == model.chain_len);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let capacity = usize::from(cursor.next_u8() % (MAX_PAGES.saturating_add(1)));
    let table = MappingTable::with_capacity(capacity);
    let mut models = Vec::new();

    while cursor.remaining() {
        match cursor.next_u8() % 10 {
            0 => allocate_page(&table, &mut models),
            1 => insert_page(&table, &mut models, &mut cursor),
            2 => delete_page(&table, &mut models, &mut cursor),
            3 => split_page(&table, &mut models, &mut cursor),
            4 => merge_page(&table, &mut models, &mut cursor),
            5 => consolidate_page(&table, &mut models, &mut cursor),
            6 => consolidate_all(&table, &mut models, &mut cursor),
            7 => check_lookup(&table, &models, &mut cursor),
            8 => check_invalid_page(&table, &models, &mut cursor),
            _ => check_scan(&table, &models, &mut cursor),
        }
        verify_pages(&table, &models);
    }
});
