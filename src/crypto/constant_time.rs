//! Utilitaires constant-time pour prevent les timing attacks
//! 
//! ATTENTION: Ce code utilise des barriers memory pour preventsr 
//! l'optimiseur de supprimer la constant-time.

use core::mem::MaybeUninit;
use zeroize::Zeroize;

/// Compare deux slices en temps constant
/// Returns true si equal, false sinon
/// Temps d'execution independsant du contenu (depends only de la longur)
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        // XOR: 0 si equal, non-zero si different
        result |= x ^ y;
    }
    
    // Conversion en bool sans branchement
    // result == 0 => true, sinon false
    subtle::black_box(result) == 0
}

/// Selection conditionnelle constant-time
/// Si choice == 1, retourne a, sinon b (sans branchement)
pub fn ct_select(a: u8, b: u8, choice: u8) -> u8 {
    // choice doit be 0 ou 1
    // si choice = 1: mask = 0xFF, retourne a
    // si choice = 0: mask = 0x00, retourne b
    let mask = -(choice as i8) as u8;
    b ^ (mask & (a ^ b))
}

/// Copie conditionnelle constant-time
/// Si choice == 1, copie src vers dst
pub fn ct_copy(dst: &mut [u8], src: &[u8], choice: u8