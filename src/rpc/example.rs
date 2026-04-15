use axum::Json;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

// Structure for the requests RPC
#[derive(Serialize, Deserialize)]
struct RpcRequest {
    method: String,
    params: Vec<String>,
}

// Structure for the responses RPC
#[derive(Serialize, Deserialize)]
struct RpcResponse {
    result: String,
    error: Option<String>,
}

// Fonction principale for handle the requests RPC
async fn rpc_handler(
    Json(request): Json<RpcRequest>,
    tx: mpsc::Sender<RpcRequest>,
) -> Json<RpcResponse> {
    // Gestion of requests RPC
    tx.send(request).await.unwrap();
    Json(RpcResponse {
        result: "OK".to_string(),
        error: None,
    })
}