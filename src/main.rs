use ruuf::cli::Command;
use structopt::StructOpt;

fn main() -> Result<(), &'static str> {
    // Get command.
    let cmd = Command::from_args();

    ruuf::run(&cmd)
}
