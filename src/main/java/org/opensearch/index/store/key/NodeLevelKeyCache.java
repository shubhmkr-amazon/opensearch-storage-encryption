/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.security.Key;
import java.util.Objects;
import java.util.concurrent.CompletionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.store.CryptoDirectoryFactory;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

/**
 * Node-level cache for encryption keys used across all shards.
 * Provides centralized key management with global TTL configuration.
 * 
 * <p>This cache focuses solely on caching functionality, delegating health
 * monitoring and block management to {@link MasterKeyHealthMonitor}.
 * 
 * <p>Failure Handling Strategy:
 * <ul>
 *   <li>Keys are refreshed in background at TTL intervals (default: 1 hour)</li>
 *   <li>On refresh failure, old key is retained temporarily</li>
 *   <li>Failures are reported to MasterKeyHealthMonitor for block management</li>
 *   <li>System automatically recovers when Master Key Provider is restored</li>
 * </ul>
 * 
 * @opensearch.internal
 */
public class NodeLevelKeyCache {

    private static final Logger logger = LogManager.getLogger(NodeLevelKeyCache.class);

    private static NodeLevelKeyCache INSTANCE;

    private final LoadingCache<EpochCacheKey, Key> keyCache;
    private final long keyExpiryDuration;
    private final MasterKeyHealthMonitor healthMonitor;

    /**
     * Cache key that extends the shard identity with a key-rotation epoch.
     *
     * <p>{@link ShardCacheKey} is intentionally shared across per-shard registries and must not gain an
     * epoch dimension. Key material, however, is cached per (shard, epoch) so that both the old and new
     * epoch keys can be resident simultaneously during an online rotation.
     */
    private static final class EpochCacheKey {
        private final ShardCacheKey shardKey;
        private final int epoch;

        EpochCacheKey(ShardCacheKey shardKey, int epoch) {
            this.shardKey = shardKey;
            this.epoch = epoch;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof EpochCacheKey other)) {
                return false;
            }
            return epoch == other.epoch && shardKey.equals(other.shardKey);
        }

        @Override
        public int hashCode() {
            return 31 * shardKey.hashCode() + epoch;
        }

        @Override
        public String toString() {
            return shardKey.toString() + "-epoch-" + epoch;
        }
    }

    /**
     * Initializes the singleton instance with node-level settings and health monitor.
     * This should be called once during plugin initialization, after MasterKeyHealthMonitor
     * has been initialized.
     * 
     * @param nodeSettings the node settings containing global TTL configuration
     * @param healthMonitor the health monitor for failure/success reporting
     */
    public static synchronized void initialize(Settings nodeSettings, MasterKeyHealthMonitor healthMonitor) {
        if (INSTANCE == null) {
            TimeValue expiryInterval = CryptoDirectoryFactory.NODE_KEY_EXPIRY_INTERVAL_SETTING.get(nodeSettings);
            long keyExpiryDuration = expiryInterval.getSeconds();

            INSTANCE = new NodeLevelKeyCache(keyExpiryDuration, healthMonitor);

            if (keyExpiryDuration < 0) {
                logger.info("Initialized NodeLevelKeyCache with no expiry (keys cached forever)");
            } else {
                logger.info("Initialized NodeLevelKeyCache with expiry interval: {}", expiryInterval);
            }
        }
    }

    /**
     * Gets the singleton instance.
     * 
     * @return the NodeLevelKeyCache instance
     * @throws IllegalStateException if the cache has not been initialized
     */
    public static NodeLevelKeyCache getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException("NodeLevelKeyCache not initialized.");
        }
        return INSTANCE;
    }

    /**
     * Constructs the cache with expiration configuration.
     * Refresh is handled manually by MasterKeyHealthMonitor to avoid reload storms.
     * 
     * @param keyExpiryDuration expiration duration in seconds (-1 or 0 means never expire)
     * @param healthMonitor the health monitor for failure/success reporting
     */
    private NodeLevelKeyCache(long keyExpiryDuration, MasterKeyHealthMonitor healthMonitor) {
        this.keyExpiryDuration = keyExpiryDuration;
        this.healthMonitor = Objects.requireNonNull(healthMonitor, "healthMonitor cannot be null");

        // Suppress Caffeine's internal logging to reduce log spam during key reload failures
        // This prevents duplicate exception logging from Caffeine's BoundedLocalCache
        java.util.logging.Logger.getLogger("com.github.benmanes.caffeine.cache").setLevel(java.util.logging.Level.SEVERE);

        // Create cache with expiration only
        // Refresh is handled manually by MasterKeyHealthMonitor to avoid reload storms
        Caffeine<Object, Object> builder = Caffeine.newBuilder();

        // Only set expireAfterWrite if keyExpiryDuration is positive
        if (keyExpiryDuration > 0) {
            builder.expireAfterWrite(keyExpiryDuration, java.util.concurrent.TimeUnit.SECONDS);
        }
        // If keyExpiryDuration <= 0, cache never expires

        this.keyCache = builder.build(new CacheLoader<EpochCacheKey, Key>() {
            @Override
            public Key load(EpochCacheKey key) throws Exception {
                return loadKey(key);
            }
        });
    }

    /**
     * Loads a key from Master Key Provider during initial load or post-expiry.
     * Reports failures to health monitor, applying blocks only for critical errors.
     * 
     * @param key the shard cache key
     * @return the loaded encryption key
     * @throws Exception if key loading fails
     */
    private Key loadKey(EpochCacheKey key) throws Exception {
        String indexUuid = key.shardKey.getIndexUuid();
        String indexName = key.shardKey.getIndexName();

        // Get resolver from registry
        KeyResolver resolver = ShardKeyResolverRegistry.getResolver(indexUuid, key.shardKey.getShardId(), indexName);
        if (resolver == null) {
            throw new IllegalStateException("No resolver registered for shard: " + key);
        }

        try {
            Key loadedKey = ((DefaultKeyResolver) resolver).loadKeyFromMasterKeyProvider(key.epoch);

            // Success: Report to health monitor
            healthMonitor.reportSuccess(indexUuid, indexName);
            return loadedKey;

        } catch (Exception e) {
            // Classify the error to determine if blocks are needed
            FailureType failureType = KeyCacheException.classify(e);

            // Only report critical failures that require blocking
            // Transient failures are logged but don't trigger blocks
            if (failureType == FailureType.CRITICAL) {
                healthMonitor.reportFailure(indexUuid, indexName, e, failureType);
            } else {
                logger.warn("Transient error loading key for index {} (will retry): {}", indexName, e.getMessage());
            }

            // Re-throw to prevent caching invalid state
            if (e instanceof KeyCacheException) {
                throw e;
            }
            throw new KeyCacheException("Failed to load key for index: " + indexName + ". Error: " + e.getMessage(), null, true);
        }
    }

    /**
     * Gets a key from the cache, loading it if necessary.
     * 
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return the encryption key
     * @throws Exception if key loading fails
     */
    /**
     * Convenience overload that resolves the shard's current (write) epoch via its registered
     * resolver, then returns that epoch's key. Used by callers that are epoch-agnostic (e.g. the
     * health monitor warming the active key).
     *
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return the encryption key for the current epoch
     * @throws Exception if key loading fails
     */
    public Key get(String indexUuid, int shardId, String indexName) throws Exception {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(indexName, "indexName cannot be null");
        KeyResolver resolver = ShardKeyResolverRegistry.getResolver(indexUuid, shardId, indexName);
        int epoch = resolver != null ? resolver.getCurrentEpoch() : 0;
        return get(indexUuid, shardId, indexName, epoch);
    }

    public Key get(String indexUuid, int shardId, String indexName, int epoch) throws Exception {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(indexName, "indexName cannot be null");

        try {
            return keyCache.get(new EpochCacheKey(new ShardCacheKey(indexUuid, shardId, indexName), epoch));
        } catch (CompletionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            } else {
                throw new RuntimeException("Failed to get key from cache", cause);
            }
        }
    }

    /**
     * Evicts a key from the cache.
     * This should be called when a shard is closed.
     * 
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     */
    public void evict(String indexUuid, int shardId, String indexName) {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(indexName, "indexName cannot be null");
        // Evict every epoch cached for this shard (shard close should drop all key material).
        ShardCacheKey shardKey = new ShardCacheKey(indexUuid, shardId, indexName);
        keyCache.asMap().keySet().removeIf(k -> k.shardKey.equals(shardKey));
    }

    /**
     * Checks if a key is present in the cache (not expired).
     * Used by health monitor to determine if blocks should be applied.
     * 
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return true if key is cached and valid, false otherwise
     */
    public boolean isKeyPresentInCache(String indexUuid, int shardId, String indexName) {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(indexName, "indexName cannot be null");

        // Present if any epoch for this shard is currently cached.
        ShardCacheKey shardKey = new ShardCacheKey(indexUuid, shardId, indexName);
        return keyCache.asMap().keySet().stream().anyMatch(k -> k.shardKey.equals(shardKey));
    }

    /**
     * Manually refreshes a key in the cache by re-loading it from the Master Key Provider.
     * This is called by MasterKeyHealthMonitor during periodic health checks to prevent
     * Caffeine's reload storm issue.
     * 
     * <p>If the key is not in cache, does nothing (returns false).
     * If refresh fails, throws the original exception for proper classification.
     * 
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return true if refresh succeeded, false if key not in cache
     * @throws Exception if refresh fails with the original exception for proper error classification
     */
    public boolean refreshKey(String indexUuid, int shardId, String indexName) throws Exception {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(indexName, "indexName cannot be null");

        ShardCacheKey shardKey = new ShardCacheKey(indexUuid, shardId, indexName);

        // Snapshot the epochs currently cached for this shard; refresh each so that all live epochs
        // (old + new during a rotation) stay warm.
        java.util.List<EpochCacheKey> cachedEpochs = keyCache
            .asMap()
            .keySet()
            .stream()
            .filter(k -> k.shardKey.equals(shardKey))
            .collect(java.util.stream.Collectors.toList());

        if (cachedEpochs.isEmpty()) {
            return false;
        }

        // Get resolver and reload each cached epoch's key
        KeyResolver resolver = ShardKeyResolverRegistry.getResolver(indexUuid, shardId, indexName);
        if (resolver == null) {
            return false;
        }

        for (EpochCacheKey cacheKey : cachedEpochs) {
            Key newKey = ((DefaultKeyResolver) resolver).loadKeyFromMasterKeyProvider(cacheKey.epoch);
            keyCache.put(cacheKey, newKey);
        }

        healthMonitor.reportSuccess(indexUuid, indexName);
        return true;
    }

    /**
     * Gets the number of cached keys.
     * Useful for monitoring and testing.
     * 
     * @return the number of cached keys
     */
    public long size() {
        return keyCache.estimatedSize();
    }

    /**
     * Clears all cached keys.
     * This method is primarily for testing purposes.
     */
    public void clear() {
        keyCache.invalidateAll();
    }

    /**
     * Resets the singleton instance completely.
     * This method is primarily for testing purposes where complete cleanup is needed.
     */
    public static synchronized void reset() {
        if (INSTANCE != null) {
            INSTANCE.clear();
            INSTANCE = null;
        }
    }
}
