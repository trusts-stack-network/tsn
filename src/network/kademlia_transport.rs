//! Transport network TCP/UDP pour DHT Kademlia
//! 
//! Implements le transport network real pour les messages Kademlia avec :
//! - Sockets UDP pour les requests courtes (PING, FIND_NODE)
//! - Sockets TCP pour les transferts volumineux (STORE, responses avec beaucoup de nodes)
//! - Rate limiting par peer pour avoidr les attaques DoS
//! - Retry automatique avec backoff exponentiel
//! - Gestion robuste des timeouts et erreurs network

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc, oneshot, Mutex};
use tokio::time::{timeout, sleep};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{Bytes, BytesMut, BufMut};
use tracing::{debug, info, warn, error, trace};
use serde::{Serialize, Deserialize};

use super::kademlia_messages::{KademliaMessage, DhtError, RequestId};
use super::rate_limiter::{RateLimiter, RateLimitConfig};
use super::error::{NetworkError, Result};

/// Configuration du transport Kademlia
#[derive(Debug, Clone)]
pub struct KademliaTransportConfig {
    /// UDP listening address for short requests
    pub udp_listen_addr: SocketAddr,
    /// TCP listening address for large transfers
    pub tcp_listen_addr: SocketAddr,
    /// Timeout pour les requests UDP
    pub udp_timeout: Duration,
    /// Timeout pour les connections TCP
    pub tcp_timeout: Duration,
    /// Taille max des messages UDP (beyond on passe en TCP)
    pub udp_max_size: usize,
    /// Nombre max de connections TCP simultaneouss
    pub max_tcp_connections: usize,
    /// Configuration du rate limiting
    pub rate_limit: RateLimitConfig,
    /// Nombre max de tentatives de retry
    pub max_retries: usize,
    /// Delay initial pour le backoff exponentiel
    pub initial_backoff: Duration,
}

impl Default for KademliaTransportConfig {
    fn default() -> Self {
        Self {
            udp_listen_addr: \"0.0.0.0:8001\".parse().unwrap(),
            tcp_listen_addr: \"0.0.0.0:8002\".parse().unwrap(),
            udp_timeout: Duration::from_secs(5),
            tcp_timeout: Duration::from_secs(10),
            udp_max_size: 1400, // Safe MTU size
            max_tcp_connections: 100,
            rate_limit: RateLimitConfig::default(),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
        }
    }
}

/// Statistiques du transport
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    pub udp_messages_sent: u64,
    pub udp_messages_received: u64,
    pub tcp_messages_sent: u64,
    pub tcp_messages_received: u64,
    pub connection_errors: u64,
    pub timeout_errors: u64,
    pub rate_limit_hits: u64,
    pub active_tcp_connections: u64,
}

/// Connection TCP active avec rate limiting
#[derive(Debug)]
struct TcpConnection {
    stream: TcpStream,
    addr: SocketAddr,
    rate_limiter: RateLimiter,
    last_activity: Instant,
    buffer: BytesMut,
}

impl TcpConnection {
    fn new(stream: TcpStream, addr: SocketAddr, rate_config: RateLimitConfig) -> Self {
        Self {
            stream,
            addr,
            rate_limiter: RateLimiter::new(rate_config),
            last_activity: Instant::now(),
            buffer: BytesMut::with_capacity(8192),
        }
    }

    /// Envoie un message via TCP avec rate limiting
    async fn send_message(&mut self, message: &KademliaMessage) -> Result<()> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(NetworkError::RateLimited(format!(\"TCP peer {}\", self.addr)));
        }

        let encoded = encode_kademlia_message(message)?;
        
        // Envoie la taille du message puis le message
        self.stream.write_u32(encoded.len() as u32).await?;
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        
        self.last_activity = Instant::now();
        trace!(\"Message TCP sent vers {}: {} bytes\", self.addr, encoded.len());
        Ok(())
    }

    /// Lit un message depuis la connection TCP
    async fn read_message(&mut self) -> Result<Option<KademliaMessage>> {
        // Lit la taille du message
        let message_size = match timeout(Duration::from_secs(30), self.stream.read_u32()).await {
            Ok(Ok(size)) => size as usize,
            Ok(Err(e)) => return Err(NetworkError::Io(e)),
            Err(_) => return Ok(None), // Timeout - pas de message
        };

        if message_size > 4 * 1024 * 1024 { // 4MB max
            return Err(NetworkError::InvalidMessage(\"Message trop volumineux\".to_string()));
        }

        // Lit le message complet
        let mut message_buf = vec![0u8; message_size];
        self.stream.read_exact(&mut message_buf).await?;

        let message = decode_kademlia_message(&message_buf)?;
        self.last_activity = Instant::now();
        
        trace!(\"Message TCP received de {}: {} bytes\", self.addr, message_size);
        Ok(Some(message))
    }

    /// Verifies si la connection est inactive
    fn is_stale(&self, max_idle: Duration) -> bool {
        self.last_activity.elapsed() > max_idle
    }
}

/// Transport network principal pour Kademlia
pub struct KademliaTransport {
    config: KademliaTransportConfig,
    udp_socket: Arc<UdpSocket>,
    tcp_connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
    tcp_listener: Option<TcpListener>,
    stats: Arc<RwLock<TransportStats>>,
    
    // Channels pour les messages entrants
    message_tx: mpsc::UnboundedSender<(SocketAddr, KademliaMessage)>,
    message_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<(SocketAddr, KademliaMessage)>>>>,
    
    // Rate limiters par peer
    peer_rate_limiters: Arc<RwLock<HashMap<SocketAddr, RateLimiter>>>,
}

impl KademliaTransport {
    /// Creates un nouveau transport Kademlia
    pub async fn new(config: KademliaTransportConfig) -> Result<Self> {
        let udp_socket = UdpSocket::bind(config.udp_listen_addr).await?;
        let tcp_listener = TcpListener::bind(config.tcp_listen_addr).await?;
        
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        info!(\"Kademlia transport initialized - UDP: {}, TCP: {}\",
              config.udp_listen_addr, config.tcp_listen_addr);
        
        Ok(Self {
            config,
            udp_socket: Arc::new(udp_socket),
            tcp_connections: Arc::new(RwLock::new(HashMap::new())),
            tcp_listener: Some(tcp_listener),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            message_tx,
            message_rx: Arc::new(Mutex::new(Some(message_rx))),
            peer_rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Starts le transport (listening UDP/TCP)
    pub async fn start(&self) -> Result<()> {
        // Starts l'listening UDP
        let udp_socket = self.udp_socket.clone();
        let message_tx = self.message_tx.clone();
        let stats = self.stats.clone();
        let peer_limiters = self.peer_rate_limiters.clone();
        let rate_config = self.config.rate_limit.clone();
        
        tokio::spawn(async move {
            Self::udp_listener_loop(udp_socket, message_tx, stats, peer_limiters, rate_config).await;
        });

        // Starts l'listening TCP
        if let Some(tcp_listener) = self.tcp_listener.take() {
            let connections = self.tcp_connections.clone();
            let message_tx = self.message_tx.clone();
            let stats = self.stats.clone();
            let rate_config = self.config.rate_limit.clone();
            let max_connections = self.config.max_tcp_connections;
            
            tokio::spawn(async move {
                Self::tcp_listener_loop(tcp_listener, connections, message_tx, stats, rate_config, max_connections).await;
            });
        }

        // Starts le cleanup des connections inactive
        let connections = self.tcp_connections.clone();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            Self::connection_cleanup_loop(connections, stats).await;
        });

        info!(\"Transport Kademlia started\");
        Ok(())
    }

    /// Envoie un message Kademlia vers un peer
    pub async fn send_message(&self, addr: SocketAddr, message: KademliaMessage) -> Result<()> {
        let encoded = encode_kademlia_message(&message)?;
        
        // Choisit UDP ou TCP selon la taille du message
        if encoded.len() <= self.config.udp_max_size {
            self.send_udp_message(addr, &encoded).await
        } else {
            self.send_tcp_message(addr, &message).await
        }
    }

    /// Envoie un message via UDP
    async fn send_udp_message(&self, addr: SocketAddr, encoded: &[u8]) -> Result<()> {
        // Verifies rate limiting
        if !self.check_peer_rate_limit(addr).await {
            self.stats.write().await.rate_limit_hits += 1;
            return Err(NetworkError::RateLimited(format!(\"UDP peer {}\", addr)));
        }

        match timeout(self.config.udp_timeout, self.udp_socket.send_to(encoded, addr)).await {
            Ok(Ok(bytes_sent)) => {
                self.stats.write().await.udp_messages_sent += 1;
                trace!(\"Message UDP sent vers {}: {} bytes\", addr, bytes_sent);
                Ok(())
            },
            Ok(Err(e)) => {
                self.stats.write().await.connection_errors += 1;
                Err(NetworkError::Io(e))
            },
            Err(_) => {
                self.stats.write().await.timeout_errors += 1;
                Err(NetworkError::Timeout(tokio::time::error::Elapsed::new()))
            }
        }
    }

    /// Envoie un message via TCP (avec retry et backoff)
    async fn send_tcp_message(&self, addr: SocketAddr, message: &KademliaMessage) -> Result<()> {
        let mut retries = 0;
        let mut backoff = self.config.initial_backoff;

        loop {
            match self.send_tcp_message_once(addr, message).await {
                Ok(()) => {
                    self.stats.write().await.tcp_messages_sent += 1;
                    return Ok(());
                },
                Err(e) if retries < self.config.max_retries => {
                    warn!(\"Failure envoi TCP vers {} (tentative {}): {}\", addr, retries + 1, e);
                    retries += 1;
                    sleep(backoff).await;
                    backoff *= 2; // Backoff exponentiel
                },
                Err(e) => {
                    self.stats.write().await.connection_errors += 1;
                    return Err(e);
                }
            }
        }
    }

    /// Envoie un message TCP (une tentative)
    async fn send_tcp_message_once(&self, addr: SocketAddr, message: &KademliaMessage) -> Result<()> {
        // Essaie d'utiliser une connection existante
        {
            let connections = self.tcp_connections.read().await;
            if let Some(conn_mutex) = connections.get(&addr) {
                let mut conn = conn_mutex.lock().await;
                if let Ok(()) = conn.send_message(message).await {
                    return Ok(());
                }
                // La connection a failed, on va la delete et en create une new
            }
        }

        // Creates une new connection TCP
        let stream = timeout(self.config.tcp_timeout, TcpStream::connect(addr)).await??;
        let mut connection = TcpConnection::new(stream, addr, self.config.rate_limit.clone());
        
        // Envoie le message
        connection.send_message(message).await?;
        
        // Stocke la connection pour reuse
        let conn_mutex = Arc::new(Mutex::new(connection));
        {
            let mut connections = self.tcp_connections.write().await;
            connections.insert(addr, conn_mutex);
            self.stats.write().await.active_tcp_connections = connections.len() as u64;
        }

        Ok(())
    }

    /// Verifies le rate limiting pour un peer
    async fn check_peer_rate_limit(&self, addr: SocketAddr) -> bool {
        let mut limiters = self.peer_rate_limiters.write().await;
        let limiter = limiters.entry(addr)
            .or_insert_with(|| RateLimiter::new(self.config.rate_limit.clone()));
        limiter.check_rate_limit()
    }

    /// Retrieves le receiver pour les messages entrants
    pub async fn take_message_receiver(&self) -> Option<mpsc::UnboundedReceiver<(SocketAddr, KademliaMessage)>> {
        self.message_rx.lock().await.take()
    }

    /// Retourne les statistiques du transport
    pub async fn stats(&self) -> TransportStats {
        self.stats.read().await.clone()
    }

    /// Boucle d'listening UDP
    async fn udp_listener_loop(
        socket: Arc<UdpSocket>,
        message_tx: mpsc::UnboundedSender<(SocketAddr, KademliaMessage)>,
        stats: Arc<RwLock<TransportStats>>,
        peer_limiters: Arc<RwLock<HashMap<SocketAddr, RateLimiter>>>,
        rate_config: RateLimitConfig,
    ) {
        let mut buffer = vec![0u8; 65536];
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((size, addr)) => {
                    // Verifies rate limiting
                    let rate_ok = {
                        let mut limiters = peer_limiters.write().await;
                        let limiter = limiters.entry(addr)
                            .or_insert_with(|| RateLimiter::new(rate_config.clone()));
                        limiter.check_rate_limit()
                    };

                    if !rate_ok {
                        stats.write().await.rate_limit_hits += 1;
                        continue;
                    }

                    // Decodes le message
                    match decode_kademlia_message(&buffer[..size]) {
                        Ok(message) => {
                            stats.write().await.udp_messages_received += 1;
                            trace!(\"Message UDP received de {}: {} bytes\", addr, size);
                            
                            if let Err(_) = message_tx.send((addr, message)) {
                                error!(\"Message channel closed - shutting down UDP listener\");
                                break;
                            }
                        },
                        Err(e) => {
                            warn!(\"Failed to decode UDP message from {}: {}\", addr, e);
                        }
                    }
                },
                Err(e) => {
                    error!(\"UDP listen error: {}\", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Boucle d'listening TCP
    async fn tcp_listener_loop(
        listener: TcpListener,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
        message_tx: mpsc::UnboundedSender<(SocketAddr, KademliaMessage)>,
        stats: Arc<RwLock<TransportStats>>,
        rate_config: RateLimitConfig,
        max_connections: usize,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Verifies le nombre max de connections
                    {
                        let conns = connections.read().await;
                        if conns.len() >= max_connections {
                            warn!(\"Connection TCP rejectede de {} - limite atteinte\", addr);
                            continue;
                        }
                    }

                    let connection = Arc::new(Mutex::new(TcpConnection::new(stream, addr, rate_config.clone())));
                    
                    // Stocke la connection
                    {
                        let mut conns = connections.write().await;
                        conns.insert(addr, connection.clone());
                        stats.write().await.active_tcp_connections = conns.len() as u64;
                    }

                    // Starts la gestion de cette connection
                    let message_tx_clone = message_tx.clone();
                    let stats_clone = stats.clone();
                    let connections_clone = connections.clone();
                    
                    tokio::spawn(async move {
                        Self::handle_tcp_connection(connection, addr, message_tx_clone, stats_clone, connections_clone).await;
                    });
                },
                Err(e) => {
                    error!(\"Erreur acceptation TCP: {}\", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Manages une connection TCP individuelle
    async fn handle_tcp_connection(
        connection: Arc<Mutex<TcpConnection>>,
        addr: SocketAddr,
        message_tx: mpsc::UnboundedSender<(SocketAddr, KademliaMessage)>,
        stats: Arc<RwLock<TransportStats>>,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
    ) {
        debug!(\"Nouvelle connection TCP de {}\", addr);
        
        loop {
            let message_opt = {
                let mut conn = connection.lock().await;
                match conn.read_message().await {
                    Ok(msg_opt) => msg_opt,
                    Err(e) => {
                        debug!(\"Erreur lecture TCP de {}: {}\", addr, e);
                        break;
                    }
                }
            };

            if let Some(message) = message_opt {
                stats.write().await.tcp_messages_received += 1;
                
                if let Err(_) = message_tx.send((addr, message)) {
                    error!(\"Message channel closed - closing TCP connection {}\", addr);
                    break;
                }
            } else {
                // Pas de message - continue to listeningr
                sleep(Duration::from_millis(10)).await;
            }
        }

        // Nettoie la connection
        {
            let mut conns = connections.write().await;
            conns.remove(&addr);
            stats.write().await.active_tcp_connections = conns.len() as u64;
        }
        
        debug!(\"TCP connection closed: {}\", addr);
    }

    /// Boucle de nettoyage des connections inactive
    async fn connection_cleanup_loop(
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<TcpConnection>>>>>,
        stats: Arc<RwLock<TransportStats>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let max_idle = Duration::from_secs(300); // 5 minutes
        
        loop {
            interval.tick().await;
            
            let mut to_remove = Vec::new();
            {
                let connections_read = connections.read().await;
                for (addr, conn_mutex) in connections_read.iter() {
                    let conn = conn_mutex.lock().await;
                    if conn.is_stale(max_idle) {
                        to_remove.push(*addr);
                    }
                }
            }

            if !to_remove.is_empty() {
                let mut connections_write = connections.write().await;
                for addr in to_remove {
                    connections_write.remove(&addr);
                    debug!(\"Connection TCP inactive removede: {}\", addr);
                }
                stats.write().await.active_tcp_connections = connections_write.len() as u64;
            }
        }
    }
}

/// Encode un message Kademlia en bytes
fn encode_kademlia_message(message: &KademliaMessage) -> Result<Vec<u8>> {
    bincode::serialize(message).map_err(|e| NetworkError::Serialization(e))
}

/// Decodes un message Kademlia depuis des bytes
fn decode_kademlia_message(data: &[u8]) -> Result<KademliaMessage> {
    bincode::deserialize(data).map_err(|e| NetworkError::Serialization(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::kademlia::NodeId;
    use super::super::kademlia_messages::builders;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = KademliaTransportConfig::default();
        let transport = KademliaTransport::new(config).await.unwrap();
        
        let stats = transport.stats().await;
        assert_eq!(stats.udp_messages_sent, 0);
        assert_eq!(stats.tcp_messages_sent, 0);
    }

    #[tokio::test]
    async fn test_message_encoding() {
        let node_id = NodeId::random();
        let message = builders::ping(node_id);
        
        let encoded = encode_kademlia_message(&message).unwrap();
        let decoded = decode_kademlia_message(&encoded).unwrap();
        
        assert_eq!(message.sender_id(), decoded.sender_id());
    }
}
"