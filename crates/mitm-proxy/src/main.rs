fn main() {
    if let Err(error) = mitm_proxy::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
