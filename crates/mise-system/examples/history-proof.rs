//! Throwaway Linux measurement driver for the public production history API.
use mise_system::history::replay::{self, RollbackRequest, UndoRequest};
use std::path::PathBuf;
#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [dot, command, path, flag, reference, yes]
            if dot == "dot" && command == "rollback" && flag == "--to" && yes == "--yes" =>
        {
            replay::rollback(RollbackRequest {
                paths: vec![PathBuf::from(path)],
                to: Some(reference.clone()),
                all: false,
                dry_run: false,
                yes: true,
                force: false,
            })
            .await
        }
        [dot, command, yes] if dot == "dot" && command == "undo" && yes == "--yes" => {
            replay::undo(UndoRequest {
                reference: None,
                dry_run: false,
                yes: true,
            })
            .await
        }
        _ => eyre::bail!("expected dot rollback PATH --to REF --yes or dot undo --yes"),
    }
}
