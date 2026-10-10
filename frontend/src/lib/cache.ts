/**
 * In-Memory LRU Cache with TTL (Time-To-Live).
 *
 * Lightweight, thread-safe, and self-evicting cache using JavaScript Map insertion order.
 * - Max Capacity: 100 entries.
 * - Default TTL: 10 minutes (600,000 ms).
 * - Supported methods: get(key), set(key, value, ttlMs?), clear(), size().
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class LRUCache<T = unknown> {
  private cache: Map<string, CacheEntry<T>>;
  private readonly maxSize: number;
  private readonly defaultTtlMs: number;

  constructor(maxSize = 100, defaultTtlMs = 600_000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Retrieves an entry from cache. Refreshes LRU recency if valid and unexpired.
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);
    if (!entry) {
      return undefined;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    // Move to most recently used position (re-insert at the end of the Map)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  /**
   * Stores an entry in cache. Evicts the least recently used entry if capacity is exceeded.
   */
  set(key: string, value: T, ttlMs = this.defaultTtlMs): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Evict oldest entry (first item in Map iterator)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Clears all cached entries.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Returns current number of cached entries.
   */
  size(): number {
    return this.cache.size;
  }
}

// Global singleton for Next.js runtime across API invocations
const globalForCache = globalThis as unknown as { analysisCache?: LRUCache<any> };
export const analysisCache = globalForCache.analysisCache ?? new LRUCache(100, 600_000);
if (process.env.NODE_ENV !== 'production') {
  globalForCache.analysisCache = analysisCache;
}
