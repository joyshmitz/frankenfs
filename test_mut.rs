use std::sync::Mutex;
struct Transaction { val: u32 }
impl Transaction { fn mutate(&mut self) { self.val += 1; } }
fn main() {
    let mut tx = Some(Transaction { val: 0 });
    if let Some(t) = &mut tx {
        let m = Mutex::new(t);
        m.lock().unwrap().mutate();
    }
    println!("{}", tx.unwrap().val);
}
