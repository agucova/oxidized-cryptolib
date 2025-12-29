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

const CHINOOK_DB_URL: &str = "https://github.com/lerocha/chinook-database/raw/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite";

// Query counts for each phase
const INDEX_LOOKUPS: usize = 100;
const JOIN_QUERIES: usize = 50;
const AGGREGATION_QUERIES: usize = 30;
const RANGE_SCANS: usize = 40;
const WRITE_OPERATIONS: usize = 200;

// Synthetic data generation
const SYNTHETIC_TRACKS: usize = 50_000;
const SYNTHETIC_INVOICES: usize = 10_000;

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
        if let Ok(conn) = Connection::open(&cache_path) {
            if conn.query_row("SELECT COUNT(*) FROM Track", [], |_| Ok(())).is_ok() {
                tracing::debug!("Using cached Chinook database at {:?}", cache_path);
                return Ok(cache_path);
            }
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
/// We augment with synthetic data to create a ~50MB database that
/// exercises the filesystem meaningfully.
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
        self.workload_dir(mount_point).join("chinook.db")
    }

    /// Generate synthetic track data to bulk up the database.
    fn generate_synthetic_data(conn: &Connection, seed: u64) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        tracing::debug!("Generating synthetic data...");

        // Get existing album IDs
        let album_count: i64 = conn.query_row("SELECT MAX(AlbumId) FROM Album", [], |r| r.get(0))?;

        // Get existing media types and genres
        let media_type_count: i64 = conn.query_row("SELECT MAX(MediaTypeId) FROM MediaType", [], |r| r.get(0))?;
        let genre_count: i64 = conn.query_row("SELECT MAX(GenreId) FROM Genre", [], |r| r.get(0))?;

        // Get the max track ID
        let max_track_id: i64 = conn.query_row("SELECT MAX(TrackId) FROM Track", [], |r| r.get(0))?;

        // Generate synthetic tracks
        {
            let mut stmt = conn.prepare(
                "INSERT INTO Track (TrackId, Name, AlbumId, MediaTypeId, GenreId, Composer, Milliseconds, Bytes, UnitPrice)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            )?;

            for i in 0..SYNTHETIC_TRACKS {
                let track_id = max_track_id + 1 + i as i64;
                let name = format!("Synthetic Track {}", i);
                let album_id = 1 + rng.random_range(0..album_count as u32) as i64;
                let media_type_id = 1 + rng.random_range(0..media_type_count as u32) as i64;
                let genre_id = 1 + rng.random_range(0..genre_count as u32) as i64;
                let composer = format!("Composer {}", rng.random_range(0..1000));
                let milliseconds = 60_000 + rng.random_range(0..300_000) as i64;
                let bytes = milliseconds * 128; // ~128 bytes per ms
                let unit_price = 0.99;

                stmt.execute(params![
                    track_id, name, album_id, media_type_id, genre_id,
                    composer, milliseconds, bytes, unit_price
                ])?;
            }
        }

        // Get existing customer IDs
        let customer_count: i64 = conn.query_row("SELECT MAX(CustomerId) FROM Customer", [], |r| r.get(0))?;
        let max_invoice_id: i64 = conn.query_row("SELECT MAX(InvoiceId) FROM Invoice", [], |r| r.get(0))?;
        let max_invoice_line_id: i64 = conn.query_row("SELECT MAX(InvoiceLineId) FROM InvoiceLine", [], |r| r.get(0))?;

        // Generate synthetic invoices
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
            let max_track_id_new = max_track_id + SYNTHETIC_TRACKS as i64;

            for i in 0..SYNTHETIC_INVOICES {
                let invoice_id = max_invoice_id + 1 + i as i64;
                let customer_id = 1 + rng.random_range(0..customer_count as u32) as i64;
                let year = 2020 + rng.random_range(0..5);
                let month = 1 + rng.random_range(0..12);
                let day = 1 + rng.random_range(0..28);
                let date = format!("{:04}-{:02}-{:02} 00:00:00", year, month, day);
                let address = format!("{} Main Street", rng.random_range(1..9999));
                let city = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"][rng.random_range(0..5)];
                let country = "USA";

                // Generate 1-5 line items per invoice
                let line_count = 1 + rng.random_range(0..5);
                let mut total = 0.0f64;

                for _ in 0..line_count {
                    let track_id = 1 + rng.random_range(0..max_track_id_new as u32) as i64;
                    let unit_price = 0.99;
                    let quantity = 1 + rng.random_range(0..3) as i64;
                    total += unit_price * quantity as f64;

                    line_stmt.execute(params![invoice_line_id, invoice_id, track_id, unit_price, quantity])?;
                    invoice_line_id += 1;
                }

                invoice_stmt.execute(params![invoice_id, customer_id, date, address, city, country, total])?;
            }
        }

        tracing::debug!(
            "Generated {} synthetic tracks and {} invoices",
            SYNTHETIC_TRACKS, SYNTHETIC_INVOICES
        );

        Ok(())
    }
}

impl Default for DatabaseWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for DatabaseWorkload {
    fn name(&self) -> &str {
        "Chinook Database"
    }

    fn operation(&self) -> OperationType {
        OperationType::DatabaseWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("database".to_string(), "Chinook (music store)".to_string());
        params.insert("synthetic_tracks".to_string(), SYNTHETIC_TRACKS.to_string());
        params.insert("synthetic_invoices".to_string(), SYNTHETIC_INVOICES.to_string());
        params.insert("index_lookups".to_string(), INDEX_LOOKUPS.to_string());
        params.insert("join_queries".to_string(), JOIN_QUERIES.to_string());
        params.insert("aggregation_queries".to_string(), AGGREGATION_QUERIES.to_string());
        params.insert("range_scans".to_string(), RANGE_SCANS.to_string());
        params.insert("write_operations".to_string(), WRITE_OPERATIONS.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Ensure Chinook database is downloaded
        let cached_db = ensure_chinook_downloaded()?;

        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point))?;

        // Copy database to mount point
        tracing::debug!("Copying Chinook database to benchmark location...");
        fs::copy(&cached_db, self.database_path(mount_point))?;

        // Open and augment with synthetic data
        let conn = Connection::open(self.database_path(mount_point))?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        Self::generate_synthetic_data(&conn, self.seed)?;

        // Force checkpoint to merge WAL
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let conn = Connection::open(self.database_path(mount_point))?;

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

            for _ in 0..INDEX_LOOKUPS {
                match rng.random_range(0..3) {
                    0 => {
                        let id = 1 + rng.random_range(0..track_count as u32) as i64;
                        let mut rows = track_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    1 => {
                        let id = 1 + rng.random_range(0..artist_count as u32) as i64;
                        let mut rows = artist_stmt.query(params![id])?;
                        while let Some(row) = rows.next()? {
                            std::hint::black_box(row.get::<_, String>(1)?);
                        }
                    }
                    _ => {
                        let id = 1 + rng.random_range(0..album_count as u32) as i64;
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

            for _ in 0..JOIN_QUERIES {
                if rng.random_bool(0.5) {
                    let track_id = 1 + rng.random_range(0..track_count as u32) as i64;
                    let mut rows = stmt1.query(params![track_id])?;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, String>(0)?);
                    }
                } else {
                    let invoice_id = 1 + rng.random_range(0..invoice_count as u32) as i64;
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

            for i in 0..AGGREGATION_QUERIES {
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

            for _ in 0..RANGE_SCANS {
                if rng.random_bool(0.5) {
                    let min_ms = rng.random_range(60_000..200_000) as i64;
                    let max_ms = min_ms + rng.random_range(60_000..120_000) as i64;
                    let mut rows = stmt1.query(params![min_ms, max_ms])?;
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        std::hint::black_box(row.get::<_, i64>(2)?);
                        count += 1;
                    }
                    std::hint::black_box(count);
                } else {
                    let year = 2020 + rng.random_range(0..4);
                    let start_date = format!("{:04}-01-01", year);
                    let end_date = format!("{:04}-12-31", year);
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

            for _ in 0..WRITE_OPERATIONS {
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
                let invoice_id = 1 + rng.random_range(0..invoice_count as u32) as i64;
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
