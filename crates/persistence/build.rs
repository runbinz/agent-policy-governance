fn main() {
    // sqlx::migrate! embeds directory contents. Cargo must also notice newly
    // added migration files when reusing an incremental build directory.
    println!("cargo:rerun-if-changed=../../migrations");
}
