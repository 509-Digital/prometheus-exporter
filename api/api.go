package api

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// manifestCacheEntry holds a cached VulnerabilityManifest with its fetch timestamp.
type manifestCacheEntry struct {
	manifest  *v1beta1.VulnerabilityManifest
	fetchedAt time.Time
}

// ManifestCache is a thread-safe TTL cache for VulnerabilityManifest objects.
// Keyed by manifest name only (all manifests live in the kubescape namespace).
type ManifestCache struct {
	mu      sync.RWMutex
	entries map[string]*manifestCacheEntry
	ttl     time.Duration
}

// NewManifestCache creates a cache with the given TTL.
func NewManifestCache(ttl time.Duration) *ManifestCache {
	return &ManifestCache{
		entries: make(map[string]*manifestCacheEntry),
		ttl:     ttl,
	}
}

// Get returns a cached manifest if present and not expired, otherwise nil.
func (c *ManifestCache) Get(name string) *v1beta1.VulnerabilityManifest {
	c.mu.RLock()
	entry, ok := c.entries[name]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.fetchedAt) > c.ttl {
		// Lazily evict expired entry
		c.mu.Lock()
		delete(c.entries, name)
		c.mu.Unlock()
		return nil
	}
	return entry.manifest
}

// Set stores a manifest in the cache with the current timestamp.
func (c *ManifestCache) Set(name string, manifest *v1beta1.VulnerabilityManifest) {
	c.mu.Lock()
	c.entries[name] = &manifestCacheEntry{
		manifest:  manifest,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()
}

// Delete removes a manifest from the cache.
func (c *ManifestCache) Delete(name string) {
	c.mu.Lock()
	delete(c.entries, name)
	c.mu.Unlock()
}

type StorageClientImpl struct {
	clientset     *spdxclient.Clientset
	manifestCache *ManifestCache
}

var _ StorageClient = &StorageClientImpl{}

func NewStorageClient() *StorageClientImpl {
	clusterConfig := k8sinterface.GetK8sConfig()
	if clusterConfig == nil {
		logger.L().Fatal("error getting cluster config")
	}
	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(clusterConfig)
	if err != nil {
		logger.L().Fatal("error creating dynamic client", helpers.Error(err))
	}

	cacheTTL := parseCacheTTL()

	return &StorageClientImpl{
		clientset:     clientset,
		manifestCache: NewManifestCache(cacheTTL),
	}
}

func parseCacheTTL() time.Duration {
	val := os.Getenv("MANIFEST_CACHE_TTL")
	if val == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		logger.L().Warning("failed to parse MANIFEST_CACHE_TTL, using default 10m", helpers.String("value", val), helpers.Error(err))
		return 10 * time.Minute
	}
	return d
}

// --- Existing methods (unchanged) ---

func (sc *StorageClientImpl) WatchVulnerabilityManifestSummaries() (watch.Interface, error) {
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetVulnerabilityManifestSummaries() (*v1beta1.VulnerabilityManifestSummaryList, error) {
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	return sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) WatchWorkloadConfigurationScanSummaries() (watch.Interface, error) {
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetWorkloadConfigurationScanSummaries() (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	return sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

// --- New methods for watch-based approach ---

// GetVulnerabilityManifest fetches a single VulnerabilityManifest by name via individual Get.
// All VulnerabilityManifests live in the "kubescape" namespace.
// Individual Get returns full Grype payload data (unlike List which strips it).
func (sc *StorageClientImpl) GetVulnerabilityManifest(namespace, name string) (*v1beta1.VulnerabilityManifest, error) {
	return sc.clientset.SpdxV1beta1().VulnerabilityManifests(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

// GetManifestCached returns a VulnerabilityManifest, using the cache if available.
// Falls back to individual API Get if not cached or expired.
// The namespace parameter from summary refs is ignored for cache keys since all manifests
// live in the "kubescape" namespace (summary refs incorrectly point to workload namespaces).
func (sc *StorageClientImpl) GetManifestCached(namespace, name string) (*v1beta1.VulnerabilityManifest, error) {
	if cached := sc.manifestCache.Get(name); cached != nil {
		return cached, nil
	}
	// All manifests live in kubescape namespace regardless of what the summary ref says
	manifest, err := sc.GetVulnerabilityManifest("kubescape", name)
	if err != nil {
		return nil, err
	}
	sc.manifestCache.Set(name, manifest)
	return manifest, nil
}

// GetVulnerabilityManifestSummary fetches a single VulnerabilityManifestSummary by namespace and name.
// Individual Get returns full object including vulnerabilitiesRef (unlike List which strips it).
func (sc *StorageClientImpl) GetVulnerabilityManifestSummary(namespace, name string) (*v1beta1.VulnerabilityManifestSummary, error) {
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

// WatchApplicationProfiles creates a watch on all ApplicationProfile resources.
// Watch events include full objects (unlike List with fullSpec which is rejected).
func (sc *StorageClientImpl) WatchApplicationProfiles() (watch.Interface, error) {
	return sc.clientset.SpdxV1beta1().ApplicationProfiles("").Watch(context.Background(), metav1.ListOptions{})
}

// WatchNetworkNeighborhoods creates a watch on all NetworkNeighborhood resources.
func (sc *StorageClientImpl) WatchNetworkNeighborhoods() (watch.Interface, error) {
	return sc.clientset.SpdxV1beta1().NetworkNeighborhoods("").Watch(context.Background(), metav1.ListOptions{})
}
