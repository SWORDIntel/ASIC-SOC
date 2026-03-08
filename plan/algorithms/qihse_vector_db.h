/*
 * QIHSE - Vector Database Integration
 *
 * Integration between QIHSE search algorithms and vector databases
 * for instant access and pre-loading capabilities.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_VECTOR_DB_H
#define QIHSE_VECTOR_DB_H

#include "memory/include/qihse_uma.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VECTOR DATABASE INTEGRATION TYPES
 * ============================================================================ */

/**
 * Vector database backend types.
 */
typedef enum qihse_vector_db_backend_e {
    QIHSE_VECTOR_DB_FAISS = 0,      /* Facebook AI Similarity Search */
    QIHSE_VECTOR_DB_CHROMA = 1,     /* ChromaDB */
    QIHSE_VECTOR_DB_QDRANT = 2,     /* Qdrant */
    QIHSE_VECTOR_DB_INMEMORY = 3,   /* In-memory vector store */
    QIHSE_VECTOR_DB_AUTO = 4,       /* Auto-detect available backend */
    QIHSE_VECTOR_DB_MMAP = 5,       /* mmap file-backed persistence */
    QIHSE_VECTOR_DB_OPTANE = 6,     /* Intel Optane PMEM (Xeon servers only) */
    QIHSE_VECTOR_DB_HYBRID = 7      /* tmpfs cache + mmap + optional Optane */
} qihse_vector_db_backend_t;

/**
 * Vector database search result.
 */
typedef struct qihse_vector_result_s {
    uint64_t id;                    /* Vector ID */
    float score;                    /* Similarity score */
    float* vector;                  /* Vector data */
    size_t vector_dims;             /* Vector dimensions */
    void* metadata;                 /* Associated metadata */
    size_t metadata_size;           /* Metadata size */
} qihse_vector_result_t;

/**
 * Vector database query parameters.
 */
typedef struct qihse_vector_query_s {
    const float* query_vector;      /* Query vector */
    size_t vector_dims;             /* Vector dimensions */
    size_t top_k;                   /* Number of results to return */
    float similarity_threshold;     /* Minimum similarity threshold */
    bool include_vectors;           /* Include vector data in results */
    bool include_metadata;          /* Include metadata in results */
} qihse_vector_query_t;

/**
 * Vector database integration handle.
 */
typedef struct qihse_vector_db_s* qihse_vector_db_t;

/* ============================================================================
 * PERSISTENCE CONFIGURATION
 * ============================================================================ */

/**
 * Dynamic sync configuration (load-adaptive).
 */
typedef struct {
    uint32_t sync_interval_ms;        /* Dynamic: 100ms (idle) → 5000ms (load) */
    uint32_t batch_size;              /* Dynamic: 100 (idle) → 10000 (load) */
    uint32_t writes_per_second;       /* Current write rate (tracked) */
    bool high_load_mode;              /* Auto-detected from write rate */
    bool enable_autotune;             /* Enable dynamic adjustment */
} qihse_sync_config_t;

/**
 * Persistence configuration for HYBRID/MMAP/OPTANE backends.
 */
typedef struct {
    const char* mmap_path;            /* Path for mmap storage (required) */
    const char* tmpfs_cache_path;     /* Optional: NULL = auto-detect */
    size_t mmap_initial_size_mb;      /* Initial mmap size (grows dynamically) */
    size_t mmap_max_size_mb;          /* Max mmap size (0 = unlimited) */
    qihse_sync_config_t sync_config;  /* Dynamic sync configuration */
    bool enable_tmpfs_cache;          /* Enable per-boot tmpfs cache */
    bool enable_optane;               /* Try to use Optane PMEM (graceful fallback) */
    bool enable_file_locking;         /* Enable flock for multi-reader safety */
} qihse_persistence_config_t;

/**
 * Mission-critical diagnostics (actionable intel).
 */
typedef struct {
    char last_error[256];             /* Human-readable error */
    uint64_t last_failure_timestamp;  /* Unix timestamp */
    char recovery_action[512];        /* ACTIONABLE recovery steps */
    int failure_code;                 /* Error code */
    char failed_operation[64];        /* Operation that failed */
    uint64_t corruption_offset;       /* File offset if corruption detected */
} qihse_diagnostic_t;

/**
 * Persistence statistics (for benchmarking).
 */
typedef struct {
    uint64_t total_syncs;             /* Number of sync operations */
    uint64_t total_bytes_written;     /* Bytes written to persistent storage */
    uint64_t total_bytes_read;        /* Bytes read from persistent storage */
    uint64_t cache_hits;              /* tmpfs cache hits */
    uint64_t cache_misses;            /* tmpfs cache misses */
    double avg_sync_latency_us;       /* Average sync latency (microseconds) */
    double max_sync_latency_us;       /* Max sync latency (microseconds) */
    bool optane_available;            /* Optane PMEM detected */
    uint64_t last_sync_timestamp;     /* Last successful sync */
} qihse_persistence_stats_t;

/* ============================================================================
 * VECTOR DATABASE LIFECYCLE
 * ============================================================================ */

/**
 * Create vector database integration with QIHSE UMA.
 *
 * @param backend Vector database backend to use
 * @param uma UMA manager for memory management
 * @param db_path Path to vector database (NULL for in-memory)
 * @return Vector database handle, or NULL on failure
 */
qihse_vector_db_t qihse_vector_db_create(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path
);

/**
 * Destroy vector database integration.
 *
 * @param vdb Vector database handle to destroy
 */
void qihse_vector_db_destroy(qihse_vector_db_t vdb);

/* ============================================================================
 * VECTOR DATABASE OPERATIONS
 * ============================================================================ */

/**
 * Add vectors to the database with QIHSE-optimized placement.
 *
 * @param vdb Vector database handle
 * @param vectors Array of vectors to add
 * @param num_vectors Number of vectors
 * @param vector_dims Dimension count per vector
 * @param ids Array of vector IDs (NULL for auto-generated)
 * @param metadata Array of metadata pointers (NULL if no metadata)
 * @param metadata_sizes Array of metadata sizes
 * @return true on success, false on failure
 */
bool qihse_vector_db_add_vectors(
    qihse_vector_db_t vdb,
    const float* vectors,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids,
    const void* const* metadata,
    const size_t* metadata_sizes
);

/**
 * Search vectors with QIHSE acceleration and instant access.
 *
 * @param vdb Vector database handle
 * @param query Query parameters
 * @param results Output array for results
 * @param max_results Maximum number of results to return
 * @return Number of results found, or negative on error
 */
int qihse_vector_db_search(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results
);

/**
 * Pre-load vectors for instant access based on query pattern.
 *
 * @param vdb Vector database handle
 * @param query_vector Query vector for preloading similar vectors
 * @param vector_dims Vector dimensions
 * @param preload_radius Similarity radius for preloading
 * @return true on success, false on failure
 */
bool qihse_vector_db_preload_similar(
    qihse_vector_db_t vdb,
    const float* query_vector,
    size_t vector_dims,
    float preload_radius
);

/* ============================================================================
 * QIHSE INTEGRATION FEATURES
 * ============================================================================ */

/**
 * Enable QIHSE-accelerated search with vector database.
 *
 * @param vdb Vector database handle
 * @param enable_hilbert Enable Hilbert space expansion
 * @param enable_quantization Enable quantization optimization
 * @param enable_parallel Enable parallel search
 * @return true on success, false on failure
 */
bool qihse_vector_db_enable_acceleration(
    qihse_vector_db_t vdb,
    bool enable_hilbert,
    bool enable_quantization,
    bool enable_parallel
);

/**
 * Get performance statistics for QIHSE-vector DB integration.
 *
 * @param vdb Vector database handle
 * @param search_time_ms Average search time in milliseconds
 * @param preload_hit_rate Preload cache hit rate (0.0-1.0)
 * @param memory_efficiency Memory efficiency ratio
 * @return true on success, false on failure
 */
bool qihse_vector_db_get_stats(
    qihse_vector_db_t vdb,
    double* search_time_ms,
    double* preload_hit_rate,
    double* memory_efficiency
);

/**
 * Optimize vector database layout for QIHSE access patterns.
 *
 * @param vdb Vector database handle
 * @param target_workload Expected workload characteristics
 * @return true on success, false on failure
 */
bool qihse_vector_db_optimize_layout(
    qihse_vector_db_t vdb,
    const char* target_workload
);

/* ============================================================================
 * MEMORY SUPERPOSITION INTEGRATION
 * ============================================================================ */

/**
 * Enable memory superposition for vector data.
 *
 * @param vdb Vector database handle
 * @param superposition_state Initial superposition state
 * @param temperature_aware Enable temperature-aware placement
 * @return true on success, false on failure
 */
bool qihse_vector_db_enable_superposition(
    qihse_vector_db_t vdb,
    qihse_memory_superposition_state_t superposition_state,
    bool temperature_aware
);

/**
 * Get current memory superposition status for vectors.
 *
 * @param vdb Vector database handle
 * @param ready_percentage Percentage of vectors in ready state (0.0-1.0)
 * @param migrating_count Number of vectors currently migrating
 * @param pinned_count Number of vectors pinned to fast memory
 * @return true on success, false on failure
 */
bool qihse_vector_db_get_superposition_status(
    qihse_vector_db_t vdb,
    double* ready_percentage,
    size_t* migrating_count,
    size_t* pinned_count
);

/* ============================================================================
 * PERSISTENCE API
 * ============================================================================ */

/**
 * Initialize persistence configuration with defaults.
 *
 * @param mmap_path Path for mmap storage
 * @return Initialized persistence configuration
 */
qihse_persistence_config_t qihse_vector_db_init_persistence_config(
    const char* mmap_path
);

/**
 * Enable dynamic sync adjustment (load-adaptive batching).
 *
 * @param vdb Vector database handle
 * @param enable Enable/disable autotune
 * @param min_interval_ms Minimum sync interval
 * @param max_interval_ms Maximum sync interval
 * @return 0 on success, negative on error
 */
int qihse_vector_db_set_autosync(
    qihse_vector_db_t vdb,
    bool enable,
    uint32_t min_interval_ms,
    uint32_t max_interval_ms
);

/**
 * Force immediate sync to persistent storage.
 *
 * @param vdb Vector database handle
 * @return 0 on success, negative on error
 */
int qihse_vector_db_sync(qihse_vector_db_t vdb);

/**
 * Get persistence statistics (for benchmarking).
 *
 * @param vdb Vector database handle
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int qihse_vector_db_get_persistence_stats(
    qihse_vector_db_t vdb,
    qihse_persistence_stats_t* stats
);

/**
 * Get mission-critical diagnostics (actionable recovery).
 *
 * @param vdb Vector database handle
 * @param diagnostics Output diagnostics structure
 * @return 0 on success, negative on error
 */
int qihse_vector_db_get_diagnostics(
    qihse_vector_db_t vdb,
    qihse_diagnostic_t* diagnostics
);

/**
 * Repair corrupted database (if possible).
 *
 * @param vdb Vector database handle
 * @return 0 on success, negative on error
 */
int qihse_vector_db_repair(qihse_vector_db_t vdb);

/**
 * Check if persistence is enabled for this database.
 *
 * @param vdb Vector database handle
 * @return true if persistence is enabled, false otherwise
 */
bool qihse_vector_db_is_persistent(qihse_vector_db_t vdb);

/**
 * Get backend type name as string.
 *
 * @param backend Backend type
 * @return Backend name string (e.g., "HYBRID", "MMAP", "INMEMORY")
 */
const char* qihse_vector_db_backend_name(qihse_vector_db_backend_t backend);

/**
 * Get database file size in bytes.
 *
 * @param vdb Vector database handle
 * @return File size in bytes, or 0 if not persistent
 */
size_t qihse_vector_db_get_file_size(qihse_vector_db_t vdb);

/**
 * Validate database path and permissions.
 *
 * @param db_path Path to validate
 * @param check_write Check write permissions
 * @param error_msg Output buffer for error message (512 bytes)
 * @return 0 if valid, negative error code otherwise
 */
int qihse_vector_db_validate_path(
    const char* db_path,
    bool check_write,
    char* error_msg
);

/**
 * Print persistence configuration and status.
 *
 * @param vdb Vector database handle
 * @param verbose Print detailed statistics
 */
void qihse_vector_db_print_persistence_info(
    qihse_vector_db_t vdb,
    bool verbose
);

/**
 * Estimate memory usage for given configuration.
 *
 * @param num_vectors Number of vectors
 * @param dims Vector dimensions
 * @param backend Backend type
 * @return Estimated memory usage in bytes
 */
size_t qihse_vector_db_estimate_memory(
    size_t num_vectors,
    size_t dims,
    qihse_vector_db_backend_t backend
);

/**
 * Compact database by removing deleted vectors (future).
 * Currently a no-op as deletion is not yet implemented.
 *
 * @param vdb Vector database handle
 * @return 0 on success, negative on error
 */
int qihse_vector_db_compact(qihse_vector_db_t vdb);

/**
 * Get backend configuration as human-readable string.
 *
 * @param vdb Vector database handle
 * @param buffer Output buffer (512 bytes minimum)
 * @param buffer_size Size of output buffer
 * @return 0 on success, negative on error
 */
int qihse_vector_db_get_config_string(
    qihse_vector_db_t vdb,
    char* buffer,
    size_t buffer_size
);

/**
 * Verify database integrity.
 * Checks magic number, version, and data consistency.
 *
 * @param db_path Path to database file
 * @param diagnostics Output diagnostics (can be NULL)
 * @return 0 if valid, negative on error
 */
int qihse_vector_db_verify_integrity(
    const char* db_path,
    qihse_diagnostic_t* diagnostics
);

/**
 * Get recommended configuration for workload.
 *
 * @param num_vectors Expected number of vectors
 * @param dims Vector dimensions
 * @param writes_per_sec Expected write rate
 * @return Recommended persistence configuration
 */
qihse_persistence_config_t qihse_vector_db_get_recommended_config(
    size_t num_vectors,
    size_t dims,
    uint32_t writes_per_sec
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VECTOR_DB_H */
