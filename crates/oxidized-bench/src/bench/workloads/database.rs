//! Database Workload
//!
//! Uses the World Development Indicators (WDI) SQLite database from the World Bank.
//! This is a real ~500MB database with time-series data across countries and indicators.
//!
//! Tests realistic analytics workload patterns:
//! - Time-series queries
//! - Aggregations across countries/years
//! - Range scans
//! - Index lookups
//!
//! Database source: https://github.com/phiresky/world-development-indicators-sqlite

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::{Context, Result};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WDI_DB_URL: &str = "https://github.com/phiresky/world-development-indicators-sqlite/releases/download/v2024-05/wdi.db";
const WDI_DB_SIZE_APPROX: u64 = 500 * 1024 * 1024; // ~500MB

// Query counts for each phase
const INDICATOR_LOOKUPS: usize = 50;
const COUNTRY_QUERIES: usize = 30;
const TIME_SERIES_QUERIES: usize = 20;
const AGGREGATION_QUERIES: usize = 15;
const COMPLEX_JOINS: usize = 10;

/// Get the cache directory for oxbench.
fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("oxbench")
}

/// Get the path to the cached WDI database.
fn cached_wdi_path() -> PathBuf {
    cache_dir().join("wdi.db")
}

/// Download the WDI database if not already cached.
fn ensure_wdi_downloaded() -> Result<PathBuf> {
    let cache_path = cached_wdi_path();

    if cache_path.exists() {
        // Verify it's roughly the right size
        let metadata = fs::metadata(&cache_path)?;
        if metadata.len() > 100 * 1024 * 1024 {
            // > 100MB, probably valid
            tracing::info!("Using cached WDI database at {:?}", cache_path);
            return Ok(cache_path);
        }
        // Too small, re-download
        fs::remove_file(&cache_path)?;
    }

    // Create cache directory
    fs::create_dir_all(cache_dir())?;

    tracing::info!(
        "Downloading World Development Indicators database (~500MB)..."
    );
    tracing::info!("Source: {}", WDI_DB_URL);

    // Download with progress indication
    let response = ureq::get(WDI_DB_URL)
        .call()
        .context("Failed to download WDI database")?;

    let total_size = response
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(WDI_DB_SIZE_APPROX);

    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(&cache_path)?;

    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut downloaded = 0u64;
    let mut last_progress = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read])?;
        downloaded += bytes_read as u64;

        // Log progress every 10%
        let progress = ((downloaded * 100) / total_size) as usize;
        if progress >= last_progress + 10 {
            tracing::info!("Download progress: {}%", progress);
            last_progress = progress;
        }
    }

    file.sync_all()?;
    tracing::info!("Download complete: {} bytes", downloaded);

    Ok(cache_path)
}

/// Database Workload using World Development Indicators.
///
/// The WDI database contains:
/// - `wdi` table: Main data with country_code, indicator_code, year, value
/// - `country` table: Country metadata
/// - `indicator` table: Indicator metadata (what each code means)
/// - `series` table: Additional series information
///
/// Phases:
/// 1. Indicator lookups - Query specific indicators by code
/// 2. Country queries - Get all data for specific countries
/// 3. Time series - Query data across year ranges
/// 4. Aggregations - GROUP BY queries across countries/years
/// 5. Complex joins - Multi-table analytical queries
pub struct DatabaseWorkload {
    seed: u64,
}

impl DatabaseWorkload {
    pub fn new() -> Self {
        Self { seed: 0xDA7A_BA5E }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_database_workload")
    }

    fn database_path(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("wdi.db")
    }

    /// Get a list of common indicator codes for queries.
    fn common_indicators() -> &'static [&'static str] {
        &[
            "NY.GDP.MKTP.CD",       // GDP (current US$)
            "NY.GDP.PCAP.CD",       // GDP per capita
            "SP.POP.TOTL",          // Population, total
            "SP.DYN.LE00.IN",       // Life expectancy at birth
            "SE.ADT.LITR.ZS",       // Literacy rate
            "SL.UEM.TOTL.ZS",       // Unemployment rate
            "FP.CPI.TOTL.ZG",       // Inflation, consumer prices
            "NY.GDP.MKTP.KD.ZG",    // GDP growth (annual %)
            "EN.ATM.CO2E.PC",       // CO2 emissions per capita
            "EG.USE.ELEC.KH.PC",    // Electric power consumption
            "IT.NET.USER.ZS",       // Internet users (% of population)
            "SH.XPD.CHEX.GD.ZS",    // Health expenditure (% of GDP)
            "SE.XPD.TOTL.GD.ZS",    // Education expenditure (% of GDP)
            "NE.EXP.GNFS.ZS",       // Exports (% of GDP)
            "NE.IMP.GNFS.ZS",       // Imports (% of GDP)
        ]
    }

    /// Get a list of country codes for queries.
    fn common_countries() -> &'static [&'static str] {
        &[
            "USA", "CHN", "JPN", "DEU", "GBR", "FRA", "IND", "ITA", "BRA", "CAN",
            "RUS", "KOR", "AUS", "ESP", "MEX", "IDN", "NLD", "SAU", "TUR", "CHE",
            "ARG", "ZAF", "NGA", "EGY", "PAK", "BGD", "VNM", "THA", "MYS", "PHL",
        ]
    }
}

impl Default for DatabaseWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for DatabaseWorkload {
    fn name(&self) -> &str {
        "WDI Database"
    }

    fn operation(&self) -> OperationType {
        OperationType::DatabaseWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("database".to_string(), "World Development Indicators".to_string());
        params.insert("indicator_lookups".to_string(), INDICATOR_LOOKUPS.to_string());
        params.insert("country_queries".to_string(), COUNTRY_QUERIES.to_string());
        params.insert("time_series_queries".to_string(), TIME_SERIES_QUERIES.to_string());
        params.insert("aggregation_queries".to_string(), AGGREGATION_QUERIES.to_string());
        params.insert("complex_joins".to_string(), COMPLEX_JOINS.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Ensure WDI database is downloaded
        let cached_db = ensure_wdi_downloaded()?;

        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point))?;

        // Copy database to mount point (this tests write performance too)
        tracing::info!("Copying WDI database to benchmark location...");
        fs::copy(&cached_db, self.database_path(mount_point))?;

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let start = Instant::now();

        let conn = Connection::open(self.database_path(mount_point))?;

        // Optimize for read-heavy workload
        conn.execute_batch("PRAGMA cache_size = 10000; PRAGMA temp_store = MEMORY;")?;

        let indicators = Self::common_indicators();
        let countries = Self::common_countries();

        // ===== Phase 1: Indicator lookups =====
        {
            let mut stmt = conn.prepare(
                "SELECT country_code, year, value FROM wdi
                 WHERE indicator_code = ?1 AND value IS NOT NULL
                 ORDER BY year DESC LIMIT 100"
            )?;

            for _ in 0..INDICATOR_LOOKUPS {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let mut rows = stmt.query(params![indicator])?;
                let mut count = 0;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, String>(0)?);
                    std::hint::black_box(row.get::<_, i64>(1)?);
                    std::hint::black_box(row.get::<_, f64>(2)?);
                    count += 1;
                }
                std::hint::black_box(count);
            }
        }

        // ===== Phase 2: Country queries =====
        {
            let mut stmt = conn.prepare(
                "SELECT indicator_code, year, value FROM wdi
                 WHERE country_code = ?1 AND year >= ?2 AND value IS NOT NULL
                 ORDER BY indicator_code, year"
            )?;

            for _ in 0..COUNTRY_QUERIES {
                let country = countries[rng.random_range(0..countries.len())];
                let start_year = 1990 + rng.random_range(0..20) as i64;

                let mut rows = stmt.query(params![country, start_year])?;
                let mut count = 0;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, String>(0)?);
                    count += 1;
                }
                std::hint::black_box(count);
            }
        }

        // ===== Phase 3: Time series queries =====
        {
            let mut stmt = conn.prepare(
                "SELECT country_code, year, value FROM wdi
                 WHERE indicator_code = ?1
                 AND year BETWEEN ?2 AND ?3
                 AND value IS NOT NULL
                 ORDER BY country_code, year"
            )?;

            for _ in 0..TIME_SERIES_QUERIES {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let start_year = 1960 + rng.random_range(0..40) as i64;
                let end_year = start_year + 10 + rng.random_range(0..20) as i64;

                let mut rows = stmt.query(params![indicator, start_year, end_year])?;
                let mut count = 0;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, f64>(2)?);
                    count += 1;
                }
                std::hint::black_box(count);
            }
        }

        // ===== Phase 4: Aggregation queries =====
        {
            // Average by year across all countries
            let mut stmt1 = conn.prepare(
                "SELECT year, AVG(value), MIN(value), MAX(value), COUNT(*)
                 FROM wdi
                 WHERE indicator_code = ?1 AND value IS NOT NULL
                 GROUP BY year
                 ORDER BY year"
            )?;

            for _ in 0..AGGREGATION_QUERIES / 3 {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let mut rows = stmt1.query(params![indicator])?;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, f64>(1)?);
                }
            }

            // Average by country across all years
            let mut stmt2 = conn.prepare(
                "SELECT country_code, AVG(value), COUNT(*)
                 FROM wdi
                 WHERE indicator_code = ?1 AND value IS NOT NULL
                 GROUP BY country_code
                 ORDER BY AVG(value) DESC
                 LIMIT 50"
            )?;

            for _ in 0..AGGREGATION_QUERIES / 3 {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let mut rows = stmt2.query(params![indicator])?;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, String>(0)?);
                }
            }

            // Growth rates (year-over-year)
            let mut stmt3 = conn.prepare(
                "SELECT w1.country_code, w1.year,
                        (w1.value - w2.value) / w2.value * 100 as growth
                 FROM wdi w1
                 JOIN wdi w2 ON w1.country_code = w2.country_code
                            AND w1.indicator_code = w2.indicator_code
                            AND w1.year = w2.year + 1
                 WHERE w1.indicator_code = ?1
                   AND w1.value IS NOT NULL AND w2.value IS NOT NULL AND w2.value != 0
                 ORDER BY growth DESC
                 LIMIT 100"
            )?;

            for _ in 0..AGGREGATION_QUERIES / 3 {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let mut rows = stmt3.query(params![indicator])?;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, f64>(2)?);
                }
            }
        }

        // ===== Phase 5: Complex joins with metadata =====
        {
            // Join with country table for region analysis
            let mut stmt1 = conn.prepare(
                "SELECT c.region, AVG(w.value) as avg_value, COUNT(DISTINCT c.country_code)
                 FROM wdi w
                 JOIN country c ON w.country_code = c.country_code
                 WHERE w.indicator_code = ?1 AND w.year = ?2 AND w.value IS NOT NULL
                 GROUP BY c.region
                 ORDER BY avg_value DESC"
            )?;

            for _ in 0..COMPLEX_JOINS / 2 {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let year = 2000 + rng.random_range(0..20) as i64;

                let mut rows = stmt1.query(params![indicator, year])?;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, Option<String>>(0)?);
                }
            }

            // Correlation between two indicators
            let mut stmt2 = conn.prepare(
                "SELECT w1.country_code, w1.value as gdp, w2.value as life_exp
                 FROM wdi w1
                 JOIN wdi w2 ON w1.country_code = w2.country_code AND w1.year = w2.year
                 WHERE w1.indicator_code = ?1
                   AND w2.indicator_code = ?2
                   AND w1.year = ?3
                   AND w1.value IS NOT NULL AND w2.value IS NOT NULL
                 ORDER BY w1.value DESC
                 LIMIT 50"
            )?;

            for _ in 0..COMPLEX_JOINS / 2 {
                let year = 2010 + rng.random_range(0..10) as i64;
                let mut rows = stmt2.query(params![
                    "NY.GDP.PCAP.CD",  // GDP per capita
                    "SP.DYN.LE00.IN",  // Life expectancy
                    year
                ])?;
                while let Some(row) = rows.next()? {
                    std::hint::black_box(row.get::<_, f64>(1)?);
                    std::hint::black_box(row.get::<_, f64>(2)?);
                }
            }
        }

        // ===== Phase 6: Write operations (simulate updates) =====
        {
            // Create a temporary analysis table
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS analysis_cache (
                    id INTEGER PRIMARY KEY,
                    indicator_code TEXT,
                    country_code TEXT,
                    start_year INTEGER,
                    end_year INTEGER,
                    avg_value REAL,
                    computed_at TEXT
                )"
            )?;

            // Insert computed results
            let mut insert_stmt = conn.prepare(
                "INSERT INTO analysis_cache (indicator_code, country_code, start_year, end_year, avg_value, computed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))"
            )?;

            for _ in 0..20 {
                let indicator = indicators[rng.random_range(0..indicators.len())];
                let country = countries[rng.random_range(0..countries.len())];
                let start_year = 2000 + rng.random_range(0..10) as i64;
                let end_year = start_year + 5;
                let avg_value = rng.random::<f64>() * 1000.0;

                insert_stmt.execute(params![indicator, country, start_year, end_year, avg_value])?;
            }

            // Read back
            let mut select_stmt = conn.prepare("SELECT * FROM analysis_cache ORDER BY id DESC LIMIT 10")?;
            let mut rows = select_stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, i64>(0)?);
            }
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }
}
