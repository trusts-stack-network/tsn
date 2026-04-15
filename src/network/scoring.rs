//! Peer scoring and anti-DoS system for TSN P2P network
//! 
//! Ce module implemente un system de scoring des pairs pour detect et bannir
//! les comportements abusifs. Il combine rate limiting et scoring comportemental.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::sync::Arc;

/// Score d'un pair (0-100, 100 = excellent, 0 = banni)
pub type PeerScore = u8;

/// Raisons de penalite pour un pair
#[derive(Debug, Clone, Copy)]
pub enum PenaltyReason {
    /// Trop de requests (rate limiting)
    RateLimitExceeded,
    /// Message invalid (malformed, signature incorrecte)
    InvalidMessage,
    /// Bloc invalid propage
    InvalidBlock,
    /// Transaction invalid propagee
    InvalidTransaction,
    /// Comportement de spam
    SpamBehavior,
    /// Failure de handshake repete
    HandshakeFailure,
    /// Timeout de connection
    ConnectionTimeout,
    /// Deconnection brutale repetee
    AbruptDisconnection,
}

impl PenaltyReason {
    /// Penalite associee a chaque raison (points retires du score)
    pub fn penalty_points(self) -> u8 {
        match self {
            Self::RateLimitExceeded => 5,
            Self::InvalidMessage => 10,
            Self::InvalidBlock => 25,
            Self::InvalidTransaction => 15,
            Self::SpamBehavior => 20,
            Self::HandshakeFailure => 8,
            Self::ConnectionTimeout => 3,
            Self::AbruptDisconnection => 5,
        }
    }
}

/// Statistiques d'un pair
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Score current (0-100)
    pub score: PeerScore,
    /// Nombre total de requests
    pub total_requests: u64,
    /// Nombre de messages invalids
    pub invalid_messages: u32,
    /// Derniere activity
    pub last_activity: Instant,
    /// Timestamp du ban (si banni)
    pub banned_until: Option<Instant>,
    /// Historique des penalites recentes
    pub recent_penalties: Vec<(Instant, PenaltyReason)>,
}

impl Default for PeerStats {
    fn default() -> Self {
        Self {
            score: 100, // Nouveau pair commence avec un score parfait
            total_requests: 0,
            invalid_messages: 0,
            last_activity: Instant::now(),
            banned_until: None,
            recent_penalties: Vec::new(),
        }
    }
}

/// Configuration du system de scoring
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Score minimum avant ban temporaire
    pub min_score_before_ban: PeerScore,
    /// Duration du ban temporaire
    pub ban_duration: Duration,
    /// Score minimum avant ban permanent
    pub min_score_before_permanent_ban: PeerScore,
    /// Duration de retention des penalites recentes
    pub penalty_retention_duration: Duration,
    /// Taux de recuperation du score (points par minute)
    pub score_recovery_rate: u8,
    /// Nombre max de requests par seconde avant penalite
    pub max_requests_per_second: u32,
    /// Fenbe de temps pour le rate limiting
    pub rate_limit_window: Duration,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_score_before_ban: 30,
            ban_duration: Duration::from_secs(300), // 5 minutes
            min_score_before_permanent_ban: 10,
            penalty_retention_duration: Duration::from_secs(3600), // 1 heure
            score_recovery_rate: 2, // 2 points par minute
            max_requests_per_second: 50,
            rate_limit_window: Duration::from_secs(1),
        }
    }
}

/// System de scoring des pairs avec anti-DoS
#[derive(Debug)]
pub struct PeerScoring {
    config: ScoringConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerStats>>>,
    /// Compteurs de requests pour rate limiting
    request_counters: Arc<RwLock<HashMap<SocketAddr, (u32, Instant)>>>,
}

impl PeerScoring {
    /// Creates a nouveau system de scoring
    pub fn new(config: ScoringConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            request_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a system avec la configuration by default
    pub fn default() -> Self {
        Self::new(ScoringConfig::default())
    }

    /// Checks if une request est autorisee (rate limiting + scoring)
    pub async fn check_request_allowed(&self, addr: &SocketAddr) -> bool {
        // Check if le pair est banni
        if self.is_peer_banned(addr).await {
            return false;
        }

        // Check the rate limiting
        if !self.check_rate_limit(addr).await {
            // Appliquer une penalite pour depassement de rate limit
            self.apply_penalty(addr, PenaltyReason::RateLimitExceeded).await;
            return false;
        }

        // Mettre a jour l'activity du pair
        self.update_peer_activity(addr).await;
        true
    }

    /// Checks the rate limiting pour un pair
    async fn check_rate_limit(&self, addr: &SocketAddr) -> bool {
        let mut counters = self.request_counters.write().await;
        let now = Instant::now();
        
        let entry = counters.entry(*addr).or_insert((0, now));
        
        // Reset du compteur si la fenbe est expiree
        if now.duration_since(entry.1) >= self.config.rate_limit_window {
            entry.0 = 0;
            entry.1 = now;
        }
        
        entry.0 += 1;
        entry.0 <= self.config.max_requests_per_second
    }

    /// Met a jour l'activity d'un pair
    async fn update_peer_activity(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        let stats = peers.entry(*addr).or_insert_with(PeerStats::default);
        stats.last_activity = Instant::now();
        stats.total_requests += 1;
    }

    /// Checks if un pair est currentlement banni
    pub async fn is_peer_banned(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read().await;
        if let Some(stats) = peers.get(addr) {
            if let Some(banned_until) = stats.banned_until {
                return Instant::now() < banned_until;
            }
        }
        false
    }

    /// Applique une penalite a un pair
    pub async fn apply_penalty(&self, addr: &SocketAddr, reason: PenaltyReason) {
        let mut peers = self.peers.write().await;
        let stats = peers.entry(*addr).or_insert_with(PeerStats::default);
        
        // Ajouter la penalite a l'historique
        stats.recent_penalties.push((Instant::now(), reason));
        
        // Nettoyer les oldnes penalites
        let cutoff = Instant::now() - self.config.penalty_retention_duration;
        stats.recent_penalties.retain(|(timestamp, _)| *timestamp > cutoff);
        
        // Appliquer la penalite au score
        let penalty = reason.penalty_points();
        stats.score = stats.score.saturating_sub(penalty);
        
        // Incrementer le compteur de messages invalids si applicable
        match reason {
            PenaltyReason::InvalidMessage 
            | PenaltyReason::InvalidBlock 
            | PenaltyReason::InvalidTransaction => {
                stats.invalid_messages += 1;
            }
            _ => {}
        }
        
        // Check if le pair doit be banni
        if stats.score <= self.config.min_score_before_permanent_ban {
            // Ban permanent (very long)
            stats.banned_until = Some(Instant::now() + Duration::from_secs(86400 * 7)); // 7 jours
            tracing::warn!("Peer {} permanently banned (score: {})", addr, stats.score);
        } else if stats.score <= self.config.min_score_before_ban {
            // Ban temporaire
            stats.banned_until = Some(Instant::now() + self.config.ban_duration);
            tracing::warn!("Peer {} temporarily banned (score: {})", addr, stats.score);
        }
        
        tracing::debug!("Applied penalty {:?} to peer {} (new score: {})", reason, addr, stats.score);
    }

    /// Recupere le score d'un pair
    pub async fn get_peer_score(&self, addr: &SocketAddr) -> PeerScore {
        let peers = self.peers.read().await;
        peers.get(addr).map(|stats| stats.score).unwrap_or(100)
    }

    /// Recupere les statistiques completes d'un pair
    pub async fn get_peer_stats(&self, addr: &SocketAddr) -> Option<PeerStats> {
        let peers = self.peers.read().await;
        peers.get(addr).cloned()
    }

    /// Recupere la liste des pairs bannis
    pub async fn get_banned_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let now = Instant::now();
        
        peers.iter()
            .filter_map(|(addr, stats)| {
                if let Some(banned_until) = stats.banned_until {
                    if now < banned_until {
                        return Some(*addr);
                    }
                }
                None
            })
            .collect()
    }

    /// Debannit manuellement un pair (pour les admins)
    pub async fn unban_peer(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(stats) = peers.get_mut(addr) {
            stats.banned_until = None;
            stats.score = 50; // Score de rehabilitation
            tracing::info!("Peer {} manually unbanned", addr);
        }
    }

    /// Tache de maintenance periodic (recuperation des scores)
    pub async fn maintenance_task(&self) {
        let mut peers = self.peers.write().await;
        let now = Instant::now();
        
        for (addr, stats) in peers.iter_mut() {
            // Recuperation graduelle du score
            if stats.score < 100 {
                let minutes_since_last_activity = now.duration_since(stats.last_activity).as_secs() / 60;
                let recovery_points = (minutes_since_last_activity as u8).saturating_mul(self.config.score_recovery_rate);
                stats.score = (stats.score + recovery_points).min(100);
            }
            
            // Nettoyer les bans expires
            if let Some(banned_until) = stats.banned_until {
                if now >= banned_until {
                    stats.banned_until = None;
                    tracing::info!("Ban expired for peer {}", addr);
                }
            }
            
            // Nettoyer les oldnes penalites
            let cutoff = now - self.config.penalty_retention_duration;
            stats.recent_penalties.retain(|(timestamp, _)| *timestamp > cutoff);
        }
        
        // Nettoyer les olds compteurs de rate limiting
        let mut counters = self.request_counters.write().await;
        let cutoff = now - self.config.rate_limit_window * 2; // Garder 2x la fenbe
        counters.retain(|_, (_, timestamp)| *timestamp > cutoff);
        
        tracing::debug!("Peer scoring maintenance completeed");
    }

    /// Recupere des statistiques globales du system
    pub async fn get_global_stats(&self) -> GlobalScoringStats {
        let peers = self.peers.read().await;
        let now = Instant::now();
        
        let total_peers = peers.len();
        let banned_peers = peers.values()
            .filter(|stats| {
                if let Some(banned_until) = stats.banned_until {
                    now < banned_until
                } else {
                    false
                }
            })
            .count();
        
        let low_score_peers = peers.values()
            .filter(|stats| stats.score < 50)
            .count();
        
        let avg_score = if total_peers > 0 {
            peers.values().map(|stats| stats.score as u32).sum::<u32>() / total_peers as u32
        } else {
            0
        } as u8;
        
        GlobalScoringStats {
            total_peers,
            banned_peers,
            low_score_peers,
            avg_score,
        }
    }
}

/// Statistiques globales du system de scoring
#[derive(Debug, Clone)]
pub struct GlobalScoringStats {
    pub total_peers: usize,
    pub banned_peers: usize,
    pub low_score_peers: usize,
    pub avg_score: PeerScore,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }
    
    #[tokio::test]
    async fn test_new_peer_has_perfect_score() {
        let scoring = PeerScoring::default();
        let addr = test_addr();
        
        let score = scoring.get_peer_score(&addr).await;
        assert_eq!(score, 100);
    }
    
    #[tokio::test]
    async fn test_penalty_reduces_score() {
        let scoring = PeerScoring::default();
        let addr = test_addr();
        
        scoring.apply_penalty(&addr, PenaltyReason::InvalidMessage).await;
        let score = scoring.get_peer_score(&addr).await;
        assert_eq!(score, 90); // 100 - 10
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = ScoringConfig::default();
        config.max_requests_per_second = 2;
        let scoring = PeerScoring::new(config);
        let addr = test_addr();
        
        // Firsts requests OK
        assert!(scoring.check_request_allowed(&addr).await);
        assert!(scoring.check_request_allowed(&addr).await);
        
        // Troisieme request bloquee
        assert!(!scoring.check_request_allowed(&addr).await);
    }
    
    #[tokio::test]
    async fn test_ban_system() {
        let mut config = ScoringConfig::default();
        config.min_score_before_ban = 50;
        let scoring = PeerScoring::new(config);
        let addr = test_addr();
        
        // Appliquer assez de penalites pour declencher un ban
        for _ in 0..6 {
            scoring.apply_penalty(&addr, PenaltyReason::InvalidMessage).await;
        }
        
        assert!(scoring.is_peer_banned(&addr).await);
        assert!(!scoring.check_request_allowed(&addr).await);
    }
}