// ZST — Logique d'execution Mint/Burn
// Applique les operations sur l'state de la reserve

use crate::stablecoin::config::StablecoinConfig;
use crate::stablecoin::errors::StablecoinError;
use crate::stablecoin::reserve::ReserveEngine;
use crate::stablecoin::types::*;

/// Gestionnaire des operations mint/burn
pub struct MintBurnManager {
    engine: ReserveEngine,
}

impl MintBurnManager {
    pub fn new(config: StablecoinConfig) -> Self {
        Self {
            engine: ReserveEngine::new(config),
        }
    }

    pub fn engine(&self) -> &ReserveEngine {
        &self.engine
    }

    /// Execute un mint ZST: depose TSN, recoit ZST
    pub fn execute_mint_zst(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;

        let result = self.engine.simulate_mint_zst(state, request.amount_in)?;

        // Verifier slippage
        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer sur l'state
        state.reserve_tsn += result.amount_in - result.fee + result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zst += result.amount_out;

        Ok(result)
    }

    /// Execute un burn ZST: brule ZST, retrieves TSN
    pub fn execute_burn_zst(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;

        // Verifier circuit breaker (sauf en mode survie ou burn ZST reste OK)
        let is_survival = self.is_circuit_breaker_active(state, current_timestamp);
        if is_survival {
            // En mode survie, seul le burn ZST est autorise, mais avec frais max
        }

        let result =
            self.engine
                .simulate_burn_zst(state, request.amount_in, current_timestamp)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer sur l'state
        let tsn_gross = self
            .engine
            .zst_to_tsn(request.amount_in, state.last_price.tsn_per_xau)?;
        state.reserve_tsn = state.reserve_tsn.saturating_sub(tsn_gross);
        state.reserve_tsn += result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zst -= request.amount_in;
        state.current_block_burned_zst += request.amount_in;

        // Check if on doit activer le circuit breaker
        let ratio = self.engine.calculate_ratio(state)?;
        if ratio < self.engine.config.circuit_breaker_ratio
            && state.circuit_breaker_activated == 0
        {
            state.circuit_breaker_activated = current_timestamp;
        }

        Ok(result)
    }

    /// Execute un mint ZRS: depose TSN, recoit ZRS
    pub fn execute_mint_zrs(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;
        self.engine
            .check_circuit_breaker(state, current_timestamp)?;

        let result = self.engine.simulate_mint_zrs(state, request.amount_in)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer
        state.reserve_tsn += result.amount_in - result.fee + result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zrs += result.amount_out;

        Ok(result)
    }

    /// Execute un burn ZRS: brule ZRS, retrieves TSN
    pub fn execute_burn_zrs(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        self.validate_common(state, current_timestamp)?;
        self.engine
            .check_circuit_breaker(state, current_timestamp)?;

        let result = self.engine.simulate_burn_zrs(state, request.amount_in)?;

        if result.amount_out < request.min_amount_out {
            return Err(StablecoinError::SlippageExceeded {
                actual: result.amount_out,
                expected: request.min_amount_out,
            });
        }

        // Appliquer
        let zrs_price = self.engine.calculate_zrs_price(state)?;
        let tsn_gross = request
            .amount_in
            .checked_mul(zrs_price)
            .ok_or(StablecoinError::ArithmeticOverflow)?
            / ATOMIC_UNIT;
        state.reserve_tsn = state.reserve_tsn.saturating_sub(tsn_gross);
        state.reserve_tsn += result.fee_reserve;
        state.treasury_tsn += result.fee_treasury;
        state.supply_zrs -= request.amount_in;

        Ok(result)
    }

    /// Dispatch une request vers la bonne methode
    pub fn execute(
        &self,
        state: &mut ReserveState,
        request: &MintBurnRequest,
        current_timestamp: u64,
    ) -> Result<MintBurnResult, StablecoinError> {
        match request.action {
            StablecoinAction::MintZST => self.execute_mint_zst(state, request, current_timestamp),
            StablecoinAction::BurnZST => self.execute_burn_zst(state, request, current_timestamp),
            StablecoinAction::MintZRS => self.execute_mint_zrs(state, request, current_timestamp),
            StablecoinAction::BurnZRS => self.execute_burn_zrs(state, request, current_timestamp),
        }
    }

    /// Reinitialise le tracking cooldown pour un nouveau bloc
    pub fn new_block(&self, state: &mut ReserveState, block_height: u64) {
        state.current_block_burned_zst = 0;
        state.current_block_height = block_height;
    }

    /// Desactive le circuit breaker si expire
    pub fn check_circuit_breaker_expiry(&self, state: &mut ReserveState, current_timestamp: u64) {
        if state.circuit_breaker_activated > 0 {
            let expiry =
                state.circuit_breaker_activated + self.engine.config.circuit_breaker_duration;
            if current_timestamp >= expiry {
                state.circuit_breaker_activated = 0;
            }
        }
    }

    // --- Helpers prives ---

    fn validate_common(
        &self,
        state: &ReserveState,
        _current_timestamp: u64,
    ) -> Result<(), StablecoinError> {
        if state.last_price.tsn_per_xau == 0 {
            return Err(StablecoinError::NoPriceAvailable);
        }
        if state.last_price.confidence == PriceConfidence::Stale {
            return Err(StablecoinError::OracleUnavailable);
        }
        Ok(())
    }

    fn is_circuit_breaker_active(&self, state: &ReserveState, current_timestamp: u64) -> bool {
        if state.circuit_breaker_activated == 0 {
            return false;
        }
        let expiry = state.circuit_breaker_activated + self.engine.config.circuit_breaker_duration;
        current_timestamp < expiry
    }
}
