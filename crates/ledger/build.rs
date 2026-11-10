fn main() {
    // Integration tests embed migrations and must notice newly added files.
    println!("cargo:rerun-if-changed=../../migrations");
}
