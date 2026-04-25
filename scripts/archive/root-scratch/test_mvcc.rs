use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct CommitSeq(u64);

struct BlockVersion {
    commit_seq: CommitSeq,
    data: Vec<u8>,
}

fn read_visible(versions: &[BlockVersion], snapshot: CommitSeq) -> Option<&[u8]> {
    let idx = versions.iter().rposition(|v| v.commit_seq <= snapshot)?;
    Some(&versions[idx].data)
}

fn main() {
    let mut versions = Vec::new();
    versions.push(BlockVersion { commit_seq: CommitSeq(1), data: vec![1, 2, 3] });
    
    let res = read_visible(&versions, CommitSeq(1));
    println!("{:?}", res);
    
    let res2 = read_visible(&versions, CommitSeq(2));
    println!("{:?}", res2);
}
