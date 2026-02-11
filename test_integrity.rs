// Quick test of integrity_test() function
use arc_primitives::self_test::integrity_test;

fn main() {
    println!("Testing FIPS integrity_test() in development mode...\n");

    match integrity_test() {
        Ok(()) => println!("\n✅ integrity_test() passed"),
        Err(e) => println!("\n❌ integrity_test() failed: {:?}", e),
    }
}
