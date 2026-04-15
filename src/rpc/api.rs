use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// Structure for stocker the informations de l'API
struct Api {
    tx: mpsc::Sender<SocketAddr>,
}

impl Api {
    async fn new(tx: mpsc::Sender<SocketAddr>) -> Self {
        Api { tx }
    }

    async fn handle_request(&self, request: Json<Request>) -> impl IntoResponse {
        match request {
            Request::GetPeers => {
                let peers = self.get_peers().await;
                (StatusCode::OK, Json(peers))
            }
            Request::GetBlocks => {
                let blocks = self.get_blocks().await;
                (StatusCode::OK, Json(blocks))
            }
            _ => (StatusCode::NOT_FOUND, "Not Found"),
        }
    }

    async fn get_peers(&self) -> Vec<SocketAddr> {
        // Retrieve the liste of peers connus
        let mut peers = Vec::new();
        // ...
        peers
    }

    async fn get_blocks(&self) -> Vec<Block> {
        // Retrieve the liste of blocs
        let mut blocks = Vec::new();
        // ...
        blocks
    }
}

// Structure for stocker the informations de the request
#[derive(Deserialize, Serialize)]
enum Request {
    GetPeers,
    GetBlocks,
}

// Structure for stocker the informations of the bloc
#[derive(Deserialize, Serialize)]
struct Block {
    // ...
}