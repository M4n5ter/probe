mod fixture;

use std::process::ExitCode;

fn main() -> ExitCode {
    match fixture::run(std::env::args().skip(1)) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
