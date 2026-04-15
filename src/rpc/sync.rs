use axum::response::IntoResponse;
use axum::extract::Query;
use axum::http::StatusCode;
use std::error::Error;
use std::fmt;

// Types d'errors pour le protocole de sync
#[derive(Debug)]
enum RpcSyncError {
    InvalidMessage,
    InvalidBlockRange,
    BlockVerificationFailed,
    IoError(std::io::Error),
}

impl fmt::Display for RpcSyncError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RpcSyncError::InvalidMessage => write!(f, "Message invalid"),
            RpcSyncError::InvalidBlockRange => write!(f, "Plage de blocs invalid"),
            RpcSyncError::BlockVerificationFailed => write!(f, "Failure de la verification du bloc"),
            RpcSyncError::IoError(e) => write!(f, "Erreur IO : {}", e),
        }
    }
}

impl Error for RpcSyncError {}

// Handler pour le protocole de sync
async fn sync_handler(
    Query(params): Query<SyncParams>,
) -> impl IntoResponse {
    // Requete de hauteur de chain
    let height = request_chain_height(&params.peer).await;

    // Telechargement de blocs par plage
    let start = params.start;
    let end = params.end;
    let blocks = download_blocks(&params.peer, start, end).await;

    // Verification et insertion des blocs
    verify_and_insert_blocks(blocks).await;

    (StatusCode::OK, "Sync reussie")
}

// Parameters pour le protocole de sync
#[derive(serde::Deserialize)]
struct SyncParams {
    peer: String,
    start: u64,
    end: u64,
}