//! Database Workload
//!
//! Uses the Chinook SQLite database (a digital music store model) with
//! additional synthetic data to stress the filesystem.
//!
//! Tests realistic database workload patterns:
//! - Index lookups and range scans
//! - Join operations across tables
//! - Aggregation queries
//! - Write operations (inserts and updates)
//!
//! Database source: https://github.com/lerocha/chinook-database

// Allow numeric casts in this module - all database ID generation involves converting
// between i64 (SQLite row IDs) and u32 (for RNG ranges). These are bounded by database
// row counts which are small enough to fit in u32.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]

use crate::bench::workloads::WorkloadConfig;
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
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

const CHINOOK_DB_URL: &str = "https://github.com/lerocha/chinook-database/raw/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite";

// Base values for full-scale workload - Query counts for each phase
const BASE_INDEX_LOOKUPS: usize = 100;
const BASE_JOIN_QUERIES: usize = 50;
const BASE_AGGREGATION_QUERIES: usize = 30;
const BASE_RANGE_SCANS: usize = 40;
const BASE_WRITE_OPERATIONS: usize = 200;

// Minimum values
const MIN_INDEX_LOOKUPS: usize = 20;
const MIN_JOIN_QUERIES: usize = 10;
const MIN_AGGREGATION_QUERIES: usize = 5;
const MIN_RANGE_SCANS: usize = 10;
const MIN_WRITE_OPERATIONS: usize = 20;

// Base values for full-scale workload - Synthetic data generation
const BASE_SYNTHETIC_TRACKS: usize = 50_000;
const BASE_SYNTHETIC_INVOICES: usize = 10_000;

// Minimum values
const MIN_SYNTHETIC_TRACKS: usize = 5_000;
const MIN_SYNTHETIC_INVOICES: usize = 1_000;

/// Phase names for progress reporting.
const DATABASE_PHASES: &[&str] = &[
    "Index lookups",
    "Join queries",
    "Aggregation queries",
    "Range scans",
    "Write operations",
    "Complex analytics",
];

/// Get the cache directory for oxbench.
fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("oxbench")
}

/// Get the path to the cached Chinook database.
fn cached_chinook_path() -> PathBuf {
    cache_dir().join("chinook.sqlite")
}

/// Download the Chinook database if not already cached.
fn ensure_chinook_downloaded() -> Result<PathBuf> {
    let cache_path = cached_chinook_path();

    if cache_path.exists() {
        // Verify it's a valid SQLite database
        if let Ok(conn) = Connection::open(&cache_path)
            && conn.query_row("SELECT COUNT(*) FROM Track", [], |_| Ok(())).is_ok() {
                tracing::debug!("Using cached Chinook database at {:?}", cache_path);
                return Ok(cache_path);
            }
        // Invalid database, re-download
        fs::remove_file(&cache_path)?;
    }

    // Create cache directory
    fs::create_dir_all(cache_dir())?;

    tracing::info!("Downloading Chinook database...");
    tracing::debug!("Source: {}", CHINOOK_DB_URL);

    let response = ureq::get(CHINOOK_DB_URL)
        .call()
        .context("Failed to download Chinook database")?;

    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(&cache_path)?;

    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        file.write_all(&buffer[..bytes_read])?;
    }

    file.sync_all()?;
    tracing::info!("Chinook database downloaded");

    Ok(cache_path)
}

/// Database Workload using Chinook + synthetic data.
///
/// The Chinook data model represents a digital media store:
/// - Artists, Albums, Tracks (music catalog)
/// - Customers, Invoices, InvoiceLines (sales data)
/// - Employees (staff hierarchy)
/// - Genres, MediaTypes, Playlists
///
/// We augment with synthetic data to create a ~50MB database (full scale)
/// that exercises the filesystem meaningfully.
pub struct DatabaseWorkload {
    config: WorkloadConfig,
    seed: u64,
    synthetic_tracks: usize,
    synthetic_invoices: usize,
    index_lookups: usize,
    join_queries: usize,
    aggregation_queries: usize,
    range_scans: usize,
    write_operations: usize,
}

impl DatabaseWorkload {
    pub fn new(config: WorkloadConfig) -> Self {
        let synthetic_tracks = config.scale_count(BASE_SYNTHETIC_TRACKS, MIN_SYNTHETIC_TRACKS);
        let synthetic_invoices = config.scale_count(BASE_SYNTHETIC_INVOICES, MIN_SYNTHETIC_INVOICES);
        let index_lookups = config.scale_count(BASE_INDEX_LOOKUPS, MIN_INDEX_LOOKUPS);
        let join_queries = config.scale_count(BASE_JOIN_QUERIES, MIN_JOIN_QUERIES);
        let aggregation_queries = config.scale_count(BASE_AGGREGATION_QUERIES, MIN_AGGREGATION_QUERIES);
        let range_scans = config.scale_count(BASE_RANGE_SCANS, MIN_RANGE_SCANS);
        let write_operations = config.scale_count(BASE_WRITE_OPERATIONS, MIN_WRITE_OPERATIONS);

        Self {
            config,
            seed: 0xDA7A_BA5E,
            synthetic_tracks,
            synthetic_invoices,
            index_lookups,
            join_queries,
            aggregation_queries,
            range_scans,
            write_operations,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_database_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn database_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("chinook.db")
    }

    /// Generate synthetic track data to bulk up the database.
    fn generate_synthetic_data(
        conn: &Connection,
        seed: u64,
        synthetic_tracks: usize,
        synthetic_invoices: usize,
    ) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        tracing::debug!("Generating synthetic data...");

        // Get existing album IDs
        let album_count: i64 = conn.query_row("SELECT MAX(AlbumId) FROM Album", [], |r| r.get(0))?;

        // Get existing media types and genres
        let media_type_count: i64 = conn.query_row("SELECT MAX(MediaTypeId) FROM MediaType", [], |r| r.get(0))?;
        let genre_count: i64 = conn.query_row("SELECT MAX(GenreId) FROM Genre", [], |r| r.get(0))?;

        // Get the max track ID
        let max_track_id: i64 = conn.query_row("SELECT MAX(TrackId) FROM Track", [], |r| r.get(0))?;

        // Generate synthetic tracks in a single transaction
        // (Without this, each INSERT would fsync individually - 50k+ fsyncs!)
        conn.execute("BEGIN TRANSACTION", [])?;
        {
            let mut stmt = conn.prepare(
                "INSERT INTO Track (TrackId, Name, AlbumId, MediaTypeId, GenreId, Composer, Milliseconds, Bytes, UnitPrice)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            )?;

            for i in 0..synthetic_tracks {
                let track_id = max_track_id + 1 + i64::try_from(i).unwrap_or(0);
                let name = format!("Synthetic Track {i}");
                let album_id = 1 + i64::from(rng.random_range(0..album_count as u32));
                let media_type_id = 1 + i64::from(rng.random_range(0..media_type_count as u32));
                let genre_id = 1 + i64::from(rng.random_range(0..genre_count as u32));
                let composer = format!("Composer {}", rng.random_range(0..1000));
                let milliseconds = 60_000 + i64::from(rng.random_range(0..300_000));
                let bytes = milliseconds * 128; // ~128 bytes per ms
                let unit_price = 0.99;

                stmt.execute(params![
                    track_id, name, album_id, media_type_id, genre_id,
                    composer, milliseconds, bytes, unit_price
                ])?;
            }
        }
        conn.execute("COMMIT", [])?;

        // Get existing customer IDs
        let customer_count: i64 = conn.query_row("SELECT MAX(CustomerId) FROM Customer", [], |r| r.get(0))?;
        let max_invoice_id: i64 = conn.query_row("SELECT MAX(InvoiceId) FROM Invoice", [], |r| r.get(0))?;
        let max_invoice_line_id: i64 = conn.query_row("SELECT MAX(InvoiceLineId) FROM InvoiceLine", [], |r| r.get(0))?;

        // Collect all valid track IDs (original + synthetic) to avoid foreign key violations
        let mut valid_track_ids = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT TrackId FROM Track ORDER BY TrackId")?;
            let track_iter = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for track_id in track_iter {
                valid_track_ids.push(track_id?);
            }
        }

        if valid_track_ids.is_empty() {
            anyhow::bail!("No tracks found in database");
        }

        // Generate synthetic invoices in a single transaction
        // (Without this, each INSERT would fsync individually - 10k+ fsyncs!)
        conn.execute("BEGIN TRANSACTION", [])?;
        {
            let mut invoice_stmt = conn.prepare(
                "INSERT INTO Invoice (InvoiceId, CustomerId, InvoiceDate, BillingAddress, BillingCity, BillingCountry, Total)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;

            let mut line_stmt = conn.prepare(
                "INSERT INTO InvoiceLine (InvoiceLineId, InvoiceId, TrackId, UnitPrice, Quantity)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            )?;

            let mut invoice_line_id = max_invoice_line_id + 1;

            for i in 0..synthetic_invoices {
                let invoice_id = max_invoice_id + 1 + i as i64;
                let customer_id = 1 + i64::from(rng.random_range(0..customer_count as u32));
                let year = 2020 + rng.random_range(0..5);
                let month = 1 + rng.random_range(0..12);
                let day = 1 + rng.random_range(0..28);
                let date = format!("{year:04}-{month:02}-{day:02} 00:00:00");
                let address = format!("{} Main Street", rng.random_range(1..9999));
                let city = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"][rng.random_range(0..5)];
                let country = "USA";

                // Generate 1-5 line items per invoice
                let line_count = 1 + rng.random_range(0..5);
                let mut total = 0.0f64;

                for _ in 0..line_count {
                    // Pick a random track from valid track IDs to avoid foreign key violations
                    let track_idx = rng.random_range(0..valid_track_ids.len() as u32) as usize;
                    let track_id = valid_track_ids[track_idx];
                    let unit_price = 0.99;
                    let quantity = 1 + i64::from(rng.random_range(0..3));
                    total += unit_price * quantity as f64;

                    line_stmt.execute(params![invoice_line_id, invoice_id, track_id, unit_price, quantity])?;
                    invoice_line_id += 1;
                }

                invoice_stmt.execute(params![invoice_id, customer_id, date, address, city, country, total])?;
            }
        }
        conn.execute("COMMIT", [])?;

        tracing::debug!(
            "Generated {} synthetic tracks and {} invoices",
            synthetic_tracks, synthetic_invoices
        );

        Ok(())
    }
}

impl Default for DatabaseWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for DatabaseWorkload {
    fn name(&self) -> &'static str {
        "Chinook Database"
    }

    fn operation(&self) -> OperationType {
        OperationType::DatabaseWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("database".to_string(), "Chinook (music store)".to_string());
        params.insert("synthetic_tracks".to_string(), self.synthetic_tracks.to_string());
        params.insert("synthetic_invoices".to_string(), self.synthetic_invoices.to_string());
        params.insert("index_lookups".to_string(), self.index_lookups.to_string());
        params.insert("join_queries".to_string(), self.join_queries.to_string());
        params.insert("aggregation_queries".to_string(), self.aggregation_queries.to_string());
        params.insert("range_scans".to_string(), self.range_scans.to_string());
        params.insert("write_operations".to_string(), self.write_operations.to_string());
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        use tracing::{debug, error};
        let total_start = Instant::now();

        // Ensure Chinook database is downloaded
        let download_start = Instant::now();
        debug!("Ensuring Chinook database is downloaded...");
        let cached_db = ensure_chinook_downloaded()
            .map_err(|e| {
                error!("Failed to download Chinook database: {}", e);
                e
            })?;
        debug!("✓ Download/cache check took {:?}", download_start.elapsed());

        // Create workload directory
        let mkdir_start = Instant::now();
        let workload_dir = self.workload_dir(mount_point, iteration);
        debug!("Creating workload directory: {}", workload_dir.display());
        fs::create_dir_all(&workload_dir)
            .map_err(|e| {
                error!("Failed to create workload directory {}: {}", workload_dir.display(), e);
                e
            })?;
        debug!("✓ mkdir took {:?}", mkdir_start.elapsed());

        // Copy database to mount point
        // Use manual copy instead of fs::copy because macOS copyfile() uses
        // clonefile/copyfile syscalls that may not work with FUSE filesystems
        let copy_start = Instant::now();
        let db_path = self.database_path(mount_point, iteration);
        debug!("Copying Chinook database from {} to {}", cached_db.display(), db_path.display());
        let file_size = fs::metadata(&cached_db)?.len();

        let mut src = fs::File::open(&cached_db).map_err(|e| {
            error!("Failed to open source file {}: {}", cached_db.display(), e);
            e
        })?;

        let mut dst = fs::File::create(&db_path).map_err(|e| {
            error!("Failed to create destination file {}: {}", db_path.display(), e);
            e
        })?;

        std::io::copy(&mut src, &mut dst).map_err(|e| {
            error!("Failed to copy data: {}", e);
            e
        })?;

        // Ensure data is flushed before opening with SQLite
        dst.sync_all()?;
        drop(dst);
        let copy_elapsed = copy_start.elapsed();
        debug!("✓ Copy {} bytes took {:?} ({:.2} MB/s)",
               file_size, copy_elapsed,
               file_size as f64 / copy_elapsed.as_secs_f64() / 1_048_576.0);

        // Open and augment with synthetic data
        let open_start = Instant::now();
        debug!("Opening database at {}", db_path.display());
        let conn = Connection::open(&db_path)
            .map_err(|e| {
                error!("Failed to open SQLite database at {}: {}", db_path.display(), e);
                e
            })?;
        debug!("✓ Open database took {:?}", open_start.elapsed());

        let pragma_start = Instant::now();
        debug!("Setting SQLite pragmas (WAL mode, disable foreign keys)");
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = OFF;")
            .map_err(|e| {
                error!("Failed to execute SQLite pragmas: {}", e);
                e
            })?;
        debug!("✓ Pragmas took {:?}", pragma_start.elapsed());

        let synthetic_start = Instant::now();
        debug!("Generating {} synthetic tracks and {} synthetic invoices",
               self.synthetic_tracks, self.synthetic_invoices);
        Self::generate_synthetic_data(&conn, self.seed, self.synthetic_tracks, self.synthetic_invoices)
            .map_err(|e| {
                error!("Failed to generate synthetic data: {}", e);
                e
            })?;
        debug!("✓ Synthetic data generation took {:?}", synthetic_start.elapsed());

        // Force checkpoint to merge WAL
        let checkpoint_start = Instant::now();
        debug!("Executing WAL checkpoint (TRUNCATE)");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| {
                error!("Failed to execute WAL checkpoint: {}", e);
                e
            })?;
        debug!("✓ WAL checkpoint took {:?}", checkpoint_start.elapsed());

        debug!("✓ Database setup completed successfully in {:?}", total_start.elapsed());
        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let conn = Connection::open(self.database_path(mount_point, iteration))?;

        // Optimize for mixed workload
        conn.execute_batch("PRAGMA cache_size = 5000; PRAGMA temp_store = MEMORY;")?;

        // Get counts for random access
        let track_count: i64 = conn.query_row("SELECT MAX(TrackId) FROM Track", [], |r| r.get(0))?;
        let artist_count: i64 = conn.query_row("SELECT MAX(ArtistId) FROM Artist", [], |r| r.get(0))?;
        let album_count: i64 = conn.query_row("SELECT MAX(AlbumId) FROM Album", [], |r| r.get(0))?;
        let _customer_count: i64 = conn.query_row("SELECT MAX(CustomerId) FROM Customer", [], |r| r.get(0))?;
        let invoice_count: i64 = conn.query_row("SELECT MAX(InvoiceId) FROM Invoice", [], |r| r.get(0))?;

        // ===== Phase 1: Index lookups (primary key access) =====
        {
            let mut track_stmt = conn.prepare("SELECT * FROM Track WHERE TrackId = ?1")?;
            let mut artist_stmt = conn.prepare("SELECT * FROM Artist WHERE ArtistId = ?1")?;
            let mut album_stmt = conn.prepare("SELECT * FROM Album WHERE AlbumId = ?1")?;

            for _ in 0..self.index_lookups {
                match rng.random_range(0..3) {
                    0 => {
                        let id = 1 + i64::from(rng.random_range(0..track_count as u32));
                        let mut rows = track_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    1 => {
                        let id = 1 + i64::from(rng.random_range(0..artist_count as u32));
                        let mut rows = artist_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    _ => {
                        let id = 1 + i64::from(rng.random_range(0..album_count as u32));
                        let mut rows = album_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                }
            }
        }

        // ===== Phase 2: Join queries =====
        {
            // Track with Album and Artist
            let mut stmt1 = conn.prepare(
                "SELECT t.Name, al.Title, ar.Name
                 FROM Track t
                 JOIN Album al ON t.AlbumId = al.AlbumId
                 JOIN Artist ar ON al.ArtistId = ar.ArtistId
                 WHERE t.TrackId = ?1"
            )?;

            // Invoice with customer and line items
            let mut stmt2 = conn.prepare(
                "SELECT i.InvoiceId, c.FirstName, c.LastName, il.Quantity, t.Name
                 FROM Invoice i
                 JOIN Customer c ON i.CustomerId = c.CustomerId
                 JOIN InvoiceLine il ON i.InvoiceId = il.InvoiceId
                 JOIN Track t ON il.TrackId = t.TrackId
                 WHERE i.InvoiceId = ?1"
            )?;

            for _ in 0..self.join_queries {
                if rng.random_bool(0.5) {
                    let track_id = 1 + i64::from(rng.random_range(0..track_count as u32));
                    let mut rows = stmt1.query(params![track_id])?;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, String>(0)?);
                    }
                } else {
                    let invoice_id = 1 + i64::from(rng.random_range(0..invoice_count as u32));
                    let mut rows = stmt2.query(params![invoice_id])?;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, i64>(0)?);
                    }
                }
            }
        }

        // ===== Phase 3: Aggregation queries =====
        {
            // Sales by country
            let mut stmt1 = conn.prepare(
                "SELECT BillingCountry, SUM(Total) as TotalSales, COUNT(*) as InvoiceCount
                 FROM Invoice
                 GROUP BY BillingCountry
                 ORDER BY TotalSales DESC
                 LIMIT 20"
            )?;

            // Track count by genre
            let mut stmt2 = conn.prepare(
                "SELECT g.Name, COUNT(*) as TrackCount, AVG(t.Milliseconds) as AvgLength
                 FROM Track t
                 JOIN Genre g ON t.GenreId = g.GenreId
                 GROUP BY g.GenreId
                 ORDER BY TrackCount DESC"
            )?;

            // Top customers
            let mut stmt3 = conn.prepare(
                "SELECT c.CustomerId, c.FirstName, c.LastName, SUM(i.Total) as TotalSpent
                 FROM Customer c
                 JOIN Invoice i ON c.CustomerId = i.CustomerId
                 GROUP BY c.CustomerId
                 ORDER BY TotalSpent DESC
                 LIMIT 50"
            )?;

            for i in 0..self.aggregation_queries {
                match i % 3 {
                    0 => {
                        let mut rows = stmt1.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, f64>(1)?);
                        }
                    }
                    1 => {
                        let mut rows = stmt2.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, i64>(1)?);
                        }
                    }
                    _ => {
                        let mut rows = stmt3.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, f64>(3)?);
                        }
                    }
                }
            }
        }

        // ===== Phase 4: Range scans =====
        {
            // Tracks by length range
            let mut stmt1 = conn.prepare(
                "SELECT TrackId, Name, Milliseconds FROM Track
                 WHERE Milliseconds BETWEEN ?1 AND ?2
                 ORDER BY Milliseconds
                 LIMIT 1000"
            )?;

            // Invoices by date range
            let mut stmt2 = conn.prepare(
                "SELECT InvoiceId, InvoiceDate, Total FROM Invoice
                 WHERE InvoiceDate BETWEEN ?1 AND ?2
                 ORDER BY InvoiceDate
                 LIMIT 500"
            )?;

            for _ in 0..self.range_scans {
                if rng.random_bool(0.5) {
                    let min_ms = i64::from(rng.random_range(60_000..200_000));
                    let max_ms = min_ms + i64::from(rng.random_range(60_000..120_000));
                    let mut rows = stmt1.query(params![min_ms, max_ms])?;
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, i64>(2)?);
                        count += 1;
                    }
                    std::hint::black_box(count);
                } else {
                    let year = 2020 + rng.random_range(0..4);
                    let start_date = format!("{year:04}-01-01");
                    let end_date = format!("{year:04}-12-31");
                    let mut rows = stmt2.query(params![start_date, end_date])?;
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, f64>(2)?);
                        count += 1;
                    }
                    std::hint::black_box(count);
                }
            }
        }

        // ===== Phase 5: Write operations =====
        {
            // Create analysis results table
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS AnalysisCache (
                    id INTEGER PRIMARY KEY,
                    query_type TEXT,
                    result_key TEXT,
                    result_value REAL,
                    computed_at TEXT
                )"
            )?;

            let mut insert_stmt = conn.prepare(
                "INSERT INTO AnalysisCache (query_type, result_key, result_value, computed_at)
                 VALUES (?1, ?2, ?3, datetime('now'))"
            )?;

            let query_types = ["genre_stats", "country_sales", "artist_popularity", "customer_value"];

            for _ in 0..self.write_operations {
                let query_type = query_types[rng.random_range(0..query_types.len())];
                let result_key = format!("key_{}", rng.random_range(0..10000));
                let result_value = rng.random::<f64>() * 10000.0;

                insert_stmt.execute(params![query_type, result_key, result_value])?;
            }

            // Read back some results
            let mut select_stmt = conn.prepare(
                "SELECT * FROM AnalysisCache ORDER BY id DESC LIMIT 50"
            )?;
            let mut rows = select_stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, i64>(0)?);
            }

            // Update some invoices (simulates business operations)
            let mut update_stmt = conn.prepare(
                "UPDATE Invoice SET Total = Total * 1.0 WHERE InvoiceId = ?1"
            )?;
            for _ in 0..50 {
                let invoice_id = 1 + i64::from(rng.random_range(0..invoice_count as u32));
                update_stmt.execute(params![invoice_id])?;
            }
        }

        // ===== Phase 6: Complex analytics =====
        {
            // Monthly revenue trend
            let mut stmt = conn.prepare(
                "SELECT strftime('%Y-%m', InvoiceDate) as Month,
                        SUM(Total) as Revenue,
                        COUNT(*) as OrderCount,
                        AVG(Total) as AvgOrderValue
                 FROM Invoice
                 GROUP BY Month
                 ORDER BY Month DESC
                 LIMIT 24"
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, f64>(1)?);
            }

            // Artist revenue (complex join with aggregation)
            let mut stmt = conn.prepare(
                "SELECT ar.Name, COUNT(DISTINCT al.AlbumId) as Albums,
                        COUNT(DISTINCT t.TrackId) as Tracks,
                        COALESCE(SUM(il.UnitPrice * il.Quantity), 0) as Revenue
                 FROM Artist ar
                 LEFT JOIN Album al ON ar.ArtistId = al.ArtistId
                 LEFT JOIN Track t ON al.AlbumId = t.AlbumId
                 LEFT JOIN InvoiceLine il ON t.TrackId = il.TrackId
                 GROUP BY ar.ArtistId
                 ORDER BY Revenue DESC
                 LIMIT 50"
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, String>(0)?);
            }
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(DATABASE_PHASES)
    }

    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let conn = Connection::open(self.database_path(mount_point, iteration))?;

        // Optimize for mixed workload
        conn.execute_batch("PRAGMA cache_size = 5000; PRAGMA temp_store = MEMORY;")?;

        // Get counts for random access
        let track_count: i64 = conn.query_row("SELECT MAX(TrackId) FROM Track", [], |r| r.get(0))?;
        let artist_count: i64 = conn.query_row("SELECT MAX(ArtistId) FROM Artist", [], |r| r.get(0))?;
        let album_count: i64 = conn.query_row("SELECT MAX(AlbumId) FROM Album", [], |r| r.get(0))?;
        let _customer_count: i64 = conn.query_row("SELECT MAX(CustomerId) FROM Customer", [], |r| r.get(0))?;
        let invoice_count: i64 = conn.query_row("SELECT MAX(InvoiceId) FROM Invoice", [], |r| r.get(0))?;

        // Helper to report progress
        let report = |phase_idx: usize, items_done: usize, items_total: usize| {
            if let Some(cb) = progress {
                cb(PhaseProgress {
                    phase_name: DATABASE_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: DATABASE_PHASES.len(),
                    items_completed: Some(items_done),
                    items_total: Some(items_total),
                });
            }
        };

        // ===== Phase 1: Index lookups (primary key access) =====
        {
            let mut track_stmt = conn.prepare("SELECT * FROM Track WHERE TrackId = ?1")?;
            let mut artist_stmt = conn.prepare("SELECT * FROM Artist WHERE ArtistId = ?1")?;
            let mut album_stmt = conn.prepare("SELECT * FROM Album WHERE AlbumId = ?1")?;

            for i in 0..self.index_lookups {
                match rng.random_range(0..3) {
                    0 => {
                        let id = 1 + i64::from(rng.random_range(0..track_count as u32));
                        let mut rows = track_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    1 => {
                        let id = 1 + i64::from(rng.random_range(0..artist_count as u32));
                        let mut rows = artist_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    _ => {
                        let id = 1 + i64::from(rng.random_range(0..album_count as u32));
                        let mut rows = album_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                }
                report(0, i + 1, self.index_lookups);
            }
        }

        // ===== Phase 2: Join queries =====
        {
            // Track with Album and Artist
            let mut stmt1 = conn.prepare(
                "SELECT t.Name, al.Title, ar.Name
                 FROM Track t
                 JOIN Album al ON t.AlbumId = al.AlbumId
                 JOIN Artist ar ON al.ArtistId = ar.ArtistId
                 WHERE t.TrackId = ?1"
            )?;

            // Invoice with customer and line items
            let mut stmt2 = conn.prepare(
                "SELECT i.InvoiceId, c.FirstName, c.LastName, il.Quantity, t.Name
                 FROM Invoice i
                 JOIN Customer c ON i.CustomerId = c.CustomerId
                 JOIN InvoiceLine il ON i.InvoiceId = il.InvoiceId
                 JOIN Track t ON il.TrackId = t.TrackId
                 WHERE i.InvoiceId = ?1"
            )?;

            for i in 0..self.join_queries {
                if rng.random_bool(0.5) {
                    let track_id = 1 + i64::from(rng.random_range(0..track_count as u32));
                    let mut rows = stmt1.query(params![track_id])?;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, String>(0)?);
                    }
                } else {
                    let invoice_id = 1 + i64::from(rng.random_range(0..invoice_count as u32));
                    let mut rows = stmt2.query(params![invoice_id])?;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, i64>(0)?);
                    }
                }
                report(1, i + 1, self.join_queries);
            }
        }

        // ===== Phase 3: Aggregation queries =====
        {
            // Sales by country
            let mut stmt1 = conn.prepare(
                "SELECT BillingCountry, SUM(Total) as TotalSales, COUNT(*) as InvoiceCount
                 FROM Invoice
                 GROUP BY BillingCountry
                 ORDER BY TotalSales DESC
                 LIMIT 20"
            )?;

            // Track count by genre
            let mut stmt2 = conn.prepare(
                "SELECT g.Name, COUNT(*) as TrackCount, AVG(t.Milliseconds) as AvgLength
                 FROM Track t
                 JOIN Genre g ON t.GenreId = g.GenreId
                 GROUP BY g.GenreId
                 ORDER BY TrackCount DESC"
            )?;

            // Top customers
            let mut stmt3 = conn.prepare(
                "SELECT c.CustomerId, c.FirstName, c.LastName, SUM(i.Total) as TotalSpent
                 FROM Customer c
                 JOIN Invoice i ON c.CustomerId = i.CustomerId
                 GROUP BY c.CustomerId
                 ORDER BY TotalSpent DESC
                 LIMIT 50"
            )?;

            for i in 0..self.aggregation_queries {
                match i % 3 {
                    0 => {
                        let mut rows = stmt1.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, f64>(1)?);
                        }
                    }
                    1 => {
                        let mut rows = stmt2.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, i64>(1)?);
                        }
                    }
                    _ => {
                        let mut rows = stmt3.query([])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, f64>(3)?);
                        }
                    }
                }
                report(2, i + 1, self.aggregation_queries);
            }
        }

        // ===== Phase 4: Range scans =====
        {
            // Tracks by length range
            let mut stmt1 = conn.prepare(
                "SELECT TrackId, Name, Milliseconds FROM Track
                 WHERE Milliseconds BETWEEN ?1 AND ?2
                 ORDER BY Milliseconds
                 LIMIT 1000"
            )?;

            // Invoices by date range
            let mut stmt2 = conn.prepare(
                "SELECT InvoiceId, InvoiceDate, Total FROM Invoice
                 WHERE InvoiceDate BETWEEN ?1 AND ?2
                 ORDER BY InvoiceDate
                 LIMIT 500"
            )?;

            for i in 0..self.range_scans {
                if rng.random_bool(0.5) {
                    let min_ms = i64::from(rng.random_range(60_000..200_000));
                    let max_ms = min_ms + i64::from(rng.random_range(60_000..120_000));
                    let mut rows = stmt1.query(params![min_ms, max_ms])?;
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, i64>(2)?);
                        count += 1;
                    }
                    std::hint::black_box(count);
                } else {
                    let year = 2020 + rng.random_range(0..4);
                    let start_date = format!("{year:04}-01-01");
                    let end_date = format!("{year:04}-12-31");
                    let mut rows = stmt2.query(params![start_date, end_date])?;
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, f64>(2)?);
                        count += 1;
                    }
                    std::hint::black_box(count);
                }
                report(3, i + 1, self.range_scans);
            }
        }

        // ===== Phase 5: Write operations =====
        {
            // Create analysis results table
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS AnalysisCache (
                    id INTEGER PRIMARY KEY,
                    query_type TEXT,
                    result_key TEXT,
                    result_value REAL,
                    computed_at TEXT
                )"
            )?;

            let mut insert_stmt = conn.prepare(
                "INSERT INTO AnalysisCache (query_type, result_key, result_value, computed_at)
                 VALUES (?1, ?2, ?3, datetime('now'))"
            )?;

            let query_types = ["genre_stats", "country_sales", "artist_popularity", "customer_value"];

            for i in 0..self.write_operations {
                let query_type = query_types[rng.random_range(0..query_types.len())];
                let result_key = format!("key_{}", rng.random_range(0..10000));
                let result_value = rng.random::<f64>() * 10000.0;

                insert_stmt.execute(params![query_type, result_key, result_value])?;
                report(4, i + 1, self.write_operations);
            }

            // Read back some results
            let mut select_stmt = conn.prepare(
                "SELECT * FROM AnalysisCache ORDER BY id DESC LIMIT 50"
            )?;
            let mut rows = select_stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, i64>(0)?);
            }

            // Update some invoices (simulates business operations)
            let mut update_stmt = conn.prepare(
                "UPDATE Invoice SET Total = Total * 1.0 WHERE InvoiceId = ?1"
            )?;
            for _ in 0..50 {
                let invoice_id = 1 + i64::from(rng.random_range(0..invoice_count as u32));
                update_stmt.execute(params![invoice_id])?;
            }
        }

        // ===== Phase 6: Complex analytics =====
        {
            // Report start of phase 6 (no item count since it's a fixed set of queries)
            report(5, 0, 2);

            // Monthly revenue trend
            let mut stmt = conn.prepare(
                "SELECT strftime('%Y-%m', InvoiceDate) as Month,
                        SUM(Total) as Revenue,
                        COUNT(*) as OrderCount,
                        AVG(Total) as AvgOrderValue
                 FROM Invoice
                 GROUP BY Month
                 ORDER BY Month DESC
                 LIMIT 24"
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, f64>(1)?);
            }

            report(5, 1, 2);

            // Artist revenue (complex join with aggregation)
            let mut stmt = conn.prepare(
                "SELECT ar.Name, COUNT(DISTINCT al.AlbumId) as Albums,
                        COUNT(DISTINCT t.TrackId) as Tracks,
                        COALESCE(SUM(il.UnitPrice * il.Quantity), 0) as Revenue
                 FROM Artist ar
                 LEFT JOIN Album al ON ar.ArtistId = al.ArtistId
                 LEFT JOIN Track t ON al.AlbumId = t.AlbumId
                 LEFT JOIN InvoiceLine il ON t.TrackId = il.TrackId
                 GROUP BY ar.ArtistId
                 ORDER BY Revenue DESC
                 LIMIT 50"
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                std::hint::black_box(row.get::<_, String>(0)?);
            }

            report(5, 2, 2);
        }

        Ok(start.elapsed())
    }
}
