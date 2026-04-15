//! Utilitaires constant-time for prevent the timing attacks
//! 
//! ATTENTION: Ce code utilise of barriers memory for preventsr 
//! l'optimiseur de supprimer the constant-time.

use core::mem::MaybeUninit;
use zeroize::Zeroize;

/// Compare deux slices in temps constant
/// Returns true if equal, false sinon
/// Temps d'execution independsant of the contenu (depends only de the longur)
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        // XOR: 0 if equal, non-zero if different
        result |= x ^ y;
    }
    
    // Conversion in bool without branchement
    // result == 0 => true, sinon false
    subtle::black_box(result) == 0
}

/// Selection conditionnelle constant-time
/// If choice == 1, returns a, otherwise b (branchless)
pub fn ct_select(a: u8, b: u8, choice: u8) -> u8 {
    // choice must be 0 or 1
    // if choice = 1: mask = 0xFF, returns a
    // if choice = 0: mask = 0x00, returns b
    let mask = -(choice as i8) as u8;
    b ^ (mask & (a ^ b))
}

/// Copie conditionnelle constant-time
/// Si choice == 1, copie src vers dst
pub fn ct_copy(dst: &mut [u8], src: &[u8], choice: u8