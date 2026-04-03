use std::fs;
fn main() {
    let code = fs::read_to_string("crates/ffs-cli/src/main.rs").unwrap();
    let new_code = code.replace("let logs = buffer.as_string();", "let logs = buffer.as_string(); println!(\"RAW LOGS:\\n{}\", logs);");
    fs::write("crates/ffs-cli/src/main.rs", new_code).unwrap();
}
