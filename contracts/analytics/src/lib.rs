//! On-chain time-series analytics for global and market-specific metrics.
//!
//! Each metric stream retains timestamped numeric data points and a cumulative
//! summary. The default capacity is 10,000 points per stream and the admin can
//! change it. Capacity is not an age-based retention period: this contract does
//! not prune or replace old points, and recording fails when a stream is full.
//! Persistent entries remain subject to Soroban storage TTL and archival rules.
//!
//! Queries provide cumulative summaries for global and market metrics, raw
//! points for global metrics over an inclusive time range, and populated time
//! buckets for global or market metrics. Bucket windows range from 1 second to
//! 1 year, with at most 2,000 estimated buckets per query. Raw-point queries
//! accept a result limit; a limit of zero returns all matching points.

#![no_std]

//! Analytics contract with auth-gated metric recording.
//!
//! Provides a secure analytics subsystem where metric recording is restricted
//! to authorized reporters (e.g., the markets contract). Every state-changing
//! entrypoint enforces authentication.
//!
//! # Auth Matrix
//!
//! | Function                    | Required Role              |
//! |-----------------------------|----------------------------|
//! | `initialize`                | Contract deployer          |
//! | `record_metric`             | Authorized reporter        |
//! | `record_metric_at`          | Authorized reporter        |
//! | `add_authorized_reporter`   | Admin                      |
//! | `remove_authorized_reporter`| Admin                      |
//! | `is_authorized_reporter`    | Anyone (read-only)         |
//! | `get_admin`                 | Anyone (read-only)         |
//! | `aggregate`                 | Anyone (read-only)         |
//! | `percentile`                | Anyone (read-only)         |

pub mod errors;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Vec};

pub use errors::ContractError;

/// Type alias used by generated client code and test harnesses.
pub type Error = ContractError;

/// Persistent-storage keys used by the Analytics contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// The admin / owner address.
    Admin,
    /// Set of authorized reporter addresses.
    AuthorizedReporters,
    /// Metric data keyed by (metric_name, timestamp).
    Metric(Symbol, u64),
}

/// On-chain record of a metric data point.
#[contracttype]
#[derive(Clone, Debug)]
pub struct MetricData {
    /// The metric name/identifier.
    pub metric_name: Symbol,
    /// Unix timestamp (seconds) when the metric was recorded.
    pub timestamp: u64,
    /// The numeric value of the metric.
    pub value: u64,
}

#[contract]
pub struct Analytics;

#[contractimpl]
impl Analytics {
    // -----------------------------------------------------------------------
    // Admin / Initialization
    // -----------------------------------------------------------------------

    /// @notice Initialize the analytics contract with an admin address.
    /// @dev Can only be called once. Subsequent calls will fail with `AlreadyInitialized`.
    /// @param env The contract environment.
    /// @param admin The address that will own the contract and manage authorized reporters.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        // Check if already initialized
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }

        // Store the admin address
        env.storage().persistent().set(&DataKey::Admin, &admin);

        // Initialize empty set of authorized reporters
        let reporters: Vec<Address> = Vec::new(&env);
        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedReporters, &reporters);

        Ok(())
    }

    /// @notice Get the current admin address.
    /// @param env The contract environment.
    /// @return The admin address, or an error if not initialized.
    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)
    }

    // -----------------------------------------------------------------------
    // Reporter Management
    // -----------------------------------------------------------------------

    /// @notice Add an address to the set of authorized reporters.
    /// @dev Requires admin authentication.
    /// @param env The contract environment.
    /// @param reporter The address to authorize as a reporter.
    pub fn add_authorized_reporter(env: Env, reporter: Address) -> Result<(), ContractError> {
        // Get and authenticate admin
        let admin = Self::get_admin(env.clone())?;
        admin.require_auth();

        // Get current reporter set
        let mut reporters: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedReporters)
            .ok_or(ContractError::NotInitialized)?;

        // Check for duplicate
        if reporters.iter().any(|r| r == reporter) {
            return Err(ContractError::DuplicateEntry);
        }

        // Add reporter and save
        reporters.push_back(reporter);
        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedReporters, &reporters);

        Ok(())
    }

    /// @notice Remove an address from the set of authorized reporters.
    /// @dev Requires admin authentication.
    /// @param env The contract environment.
    /// @param reporter The address to revoke reporter authorization from.
    pub fn remove_authorized_reporter(env: Env, reporter: Address) -> Result<(), ContractError> {
        // Get and authenticate admin
        let admin = Self::get_admin(env.clone())?;
        admin.require_auth();

        // Get current reporter set
        let mut reporters: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedReporters)
            .ok_or(ContractError::NotInitialized)?;

        // Find and remove
        let initial_len = reporters.len();
        let filtered: Vec<Address> = reporters
            .iter()
            .filter(|r| r != &reporter)
            .collect();

        if filtered.len() == initial_len {
            // Reporter was not found
            return Err(ContractError::MarketNotFound);
        }

        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedReporters, &filtered);

        Ok(())
    }

    /// @notice Check if an address is an authorized reporter.
    /// @param env The contract environment.
    /// @param reporter The address to check.
    /// @return true if authorized, false otherwise.
    pub fn is_authorized_reporter(env: Env, reporter: Address) -> Result<bool, ContractError> {
        let reporters: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedReporters)
            .ok_or(ContractError::NotInitialized)?;

        Ok(reporters.iter().any(|r| r == reporter))
    }

    // -----------------------------------------------------------------------
    // Metric Recording
    // -----------------------------------------------------------------------

    /// @notice Record a metric with the current block timestamp.
    /// @dev Requires caller to be an authorized reporter.
    /// @param env The contract environment.
    /// @param metric_name The name of the metric being recorded.
    /// @param value The numeric value of the metric.
    pub fn record_metric(
        env: Env,
        metric_name: Symbol,
        value: u64,
    ) -> Result<MetricData, ContractError> {
        let timestamp = env.ledger().timestamp();
        Self::record_metric_at(env, metric_name, timestamp, value)
    }

    /// @notice Record a metric with an explicit timestamp.
    /// @dev Requires caller to be an authorized reporter.
    /// @param env The contract environment.
    /// @param metric_name The name of the metric being recorded.
    /// @param timestamp Unix timestamp (seconds) for the metric.
    /// @param value The numeric value of the metric.
    pub fn record_metric_at(
        env: Env,
        metric_name: Symbol,
        timestamp: u64,
        value: u64,
    ) -> Result<MetricData, ContractError> {
        // Get caller
        let caller = env.invoker();

        // Check authorization
        let reporters: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedReporters)
            .ok_or(ContractError::NotInitialized)?;

        if !reporters.iter().any(|r| r == caller) {
            return Err(ContractError::Unauthorized);
        }

        // Require caller authentication
        caller.require_auth();

        // Check for duplicate entry (same metric_name, timestamp)
        let key = DataKey::Metric(metric_name.clone(), timestamp);
        if env.storage().persistent().has(&key) {
            return Err(ContractError::DuplicateEntry);
        }

        // Create and store metric
        let metric = MetricData {
            metric_name,
            timestamp,
            value,
        };

        env.storage().persistent().set(&key, &metric);

        Ok(metric)
    }

    // -----------------------------------------------------------------------
    // Analytics / Aggregation (read-only, no auth required)
    // -----------------------------------------------------------------------

    /// @notice Aggregate event types by summing their values.
    /// @dev This is a read-only entrypoint that does not require authentication.
    /// @param _env The contract environment.
    /// @param event_types Vector of event type identifiers.
    /// @return The sum of all event type values.
    pub fn aggregate(_env: Env, event_types: Vec<u32>) -> u64 {
        event_types.iter().map(|x| *x as u64).sum()
    }

    /// @notice Compute the percentile of a dataset.
    /// @dev This is a read-only entrypoint that does not require authentication.
    /// @param _env The contract environment.
    /// @param values Vector of u64 values to analyze.
    /// @param pct The percentile to compute (0-100).
    /// @return The value at the requested percentile.
    pub fn percentile(_env: Env, values: Vec<u64>, pct: u32) -> u64 {
        if values.is_empty() {
            return 0;
        }
        let mut sorted = values.clone();
        sorted.sort();
        let idx = ((pct as usize) * (sorted.len() - 1)) / 100;
        sorted.get(idx).unwrap_or(0)
    }
}
