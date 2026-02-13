package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/prometheus-exporter/api"
	"github.com/kubescape/prometheus-exporter/metrics"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/watch"
)

var errWatchClosed = errors.New("watch channel closed")

func main() {

	storageClient := api.NewStorageClient()

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		logger.L().Info("prometheus metrics server started", helpers.Int("port", 8080), helpers.String("path", "/metrics"))
		logger.L().Fatal(http.ListenAndServe(":8080", nil).Error())
	}()

	enableControlDetail := os.Getenv("ENABLE_CONTROL_DETAIL") != "false"
	enableVulnDetail := os.Getenv("ENABLE_VULNERABILITY_DETAIL") != "false"
	enableRuntime := os.Getenv("ENABLE_RUNTIME_METRICS") != "false"

	if os.Getenv("ENABLE_WORKLOAD_METRICS") == "true" || enableControlDetail || enableVulnDetail {
		go watchWorkloadConfigScanSummaries(storageClient, enableControlDetail)
		go watchWorkloadVulnScanSummaries(storageClient, enableVulnDetail)
	}

	if enableRuntime {
		logger.L().Info("runtime metrics enabled")
	}

	refreshInterval := parseDurationOrDefault("PROMETHEUS_REFRESH_INTERVAL", 120*time.Second)

	// monitor the severities in objects (no watch available)
	for {
		handleConfigScanSummaries(storageClient)
		handleVulnScanSummaries(storageClient)

		if enableRuntime {
			handleRuntimeMetrics(storageClient)
		}

		time.Sleep(refreshInterval)
	}

}

func watchWorkloadVulnScanSummaries(storageClient *api.StorageClientImpl, enableVulnDetail bool) {
	// insert the existing items
	handleWorkloadVulnScanSummaries(storageClient)

	if enableVulnDetail {
		logger.L().Info("vulnerability detail metrics enabled, loading initial data")
		handleVulnDetailMetricsInitial(storageClient)
	}

	// watch for new items
	if err := backoff.RetryNotify(func() error {
		watcher, err := storageClient.WatchVulnerabilityManifestSummaries()
		if err != nil {
			return fmt.Errorf("creating watcher: %s", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			if !chanActive {
				return errWatchClosed
			}
			if event.Type == watch.Error {
				return fmt.Errorf("watch error: %s", event.Object)
			}
			item, ok := event.Object.(*v1beta1.VulnerabilityManifestSummary)
			if !ok {
				logger.L().Warning("received unknown object", helpers.Interface("object", event.Object))
				continue
			}
			logger.L().Debug("received vuln summary event", helpers.Interface("event", event), helpers.String("name", item.Name))
			if event.Type == watch.Added || event.Type == watch.Modified {
				metrics.ProcessVulnWorkloadMetrics(&v1beta1.VulnerabilityManifestSummaryList{
					Items: []v1beta1.VulnerabilityManifestSummary{*item},
				})
				if enableVulnDetail {
					metrics.ProcessVulnDetailForSummary(item, storageClient.GetManifestCached)
				}
			}

			if event.Type == watch.Deleted {
				metrics.DeleteVulnWorkloadMetric(item)
				if enableVulnDetail {
					metrics.DeleteVulnDetailForSummary(item)
				}
			}
		}
	}, InfiniteBackOff(), func(err error, duration time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Warning("error watching workload vulnerability scan summaries", helpers.Error(err), helpers.String("retry-after", duration.String()))
		} else {
			logger.L().Debug("error watching workload vulnerability scan summaries", helpers.Error(err), helpers.String("retry-after", duration.String()))
		}
	}); err != nil {
		logger.L().Fatal("failed watching workload vulnerability scan summaries", helpers.Error(err))
	}
}

func watchWorkloadConfigScanSummaries(storageClient *api.StorageClientImpl, enableControlDetail bool) {
	// insert the existing items
	handleWorkloadConfigScanSummaries(storageClient, enableControlDetail)
	// watch for new items
	if err := backoff.RetryNotify(func() error {
		watcher, err := storageClient.WatchWorkloadConfigurationScanSummaries()
		if err != nil {
			return fmt.Errorf("creating watcher: %s", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			if !chanActive {
				return errWatchClosed
			}
			if event.Type == watch.Error {
				return fmt.Errorf("watch error: %s", event.Object)
			}
			item, ok := event.Object.(*v1beta1.WorkloadConfigurationScanSummary)
			if !ok {
				logger.L().Warning("received unknown object", helpers.Interface("object", event.Object))
				continue
			}
			logger.L().Debug("received event", helpers.Interface("event", event), helpers.String("name", item.Name))
			summaryList := &v1beta1.WorkloadConfigurationScanSummaryList{
				Items: []v1beta1.WorkloadConfigurationScanSummary{*item},
			}
			if event.Type == watch.Added || event.Type == watch.Modified {
				metrics.ProcessConfigscanWorkloadMetrics(summaryList)
				if enableControlDetail {
					metrics.ProcessControlDetailMetrics(summaryList)
				}
			}

			if event.Type == watch.Deleted {
				metrics.DeleteConfigscanWorkloadMetric(item)
				if enableControlDetail {
					metrics.DeleteControlDetailMetrics(item)
				}
			}
		}
	}, InfiniteBackOff(), func(err error, duration time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Warning("error watching workload configuration scan summaries", helpers.Error(err), helpers.String("retry-after", duration.String()))
		} else {
			logger.L().Debug("error watching workload configuration scan summaries", helpers.Error(err), helpers.String("retry-after", duration.String()))
		}
	}); err != nil {
		logger.L().Fatal("failed watching workload configuration scan summaries", helpers.Error(err))
	}
}

// handleRuntimeMetrics polls ApplicationProfile and NetworkNeighborhood resources.
// List returns metadata only (spec stripped by storage server), so individual Get
// is used for each resource to retrieve full spec with syscalls and connections.
func handleRuntimeMetrics(storageClient *api.StorageClientImpl) {
	metrics.ResetRuntimeMetrics()

	// Application Profiles
	profiles, err := storageClient.ListApplicationProfiles()
	if err != nil {
		logger.L().Warning("failed listing application profiles", helpers.Error(err))
	} else {
		loaded := 0
		for _, profile := range profiles.Items {
			fullProfile, err := storageClient.GetApplicationProfile(profile.Namespace, profile.Name)
			if err != nil {
				logger.L().Debug("failed getting application profile", helpers.String("name", profile.Name), helpers.Error(err))
				continue
			}
			metrics.ProcessRuntimeMetricsForProfile(fullProfile)
			loaded++
		}
		logger.L().Debug("runtime profile metrics refreshed", helpers.Int("profiles", loaded))
	}

	// Network Neighborhoods
	neighborhoods, err := storageClient.ListNetworkNeighborhoods()
	if err != nil {
		logger.L().Warning("failed listing network neighborhoods", helpers.Error(err))
	} else {
		loaded := 0
		for _, nn := range neighborhoods.Items {
			fullNN, err := storageClient.GetNetworkNeighborhood(nn.Namespace, nn.Name)
			if err != nil {
				logger.L().Debug("failed getting network neighborhood", helpers.String("name", nn.Name), helpers.Error(err))
				continue
			}
			metrics.ProcessRuntimeMetricsForNetwork(fullNN)
			loaded++
		}
		logger.L().Debug("runtime network metrics refreshed", helpers.Int("neighborhoods", loaded))
	}
}

func handleWorkloadConfigScanSummaries(storageClient *api.StorageClientImpl, enableControlDetail bool) {
	workloadConfigurationScanSummaries, err := storageClient.GetWorkloadConfigurationScanSummaries()
	if err != nil {
		logger.L().Warning("failed getting workload configuration scan summaries", helpers.Error(err))
		return
	}
	metrics.ProcessConfigscanWorkloadMetrics(workloadConfigurationScanSummaries)
	if enableControlDetail {
		metrics.ProcessControlDetailMetrics(workloadConfigurationScanSummaries)
	}
}

func handleConfigScanSummaries(storageClient *api.StorageClientImpl) {
	configScanSummaries, err := storageClient.GetConfigScanSummaries()
	if err != nil {
		logger.L().Warning("failed getting configuration scan summaries", helpers.Error(err))
		return
	}

	metrics.ProcessConfigscanClusterMetrics(configScanSummaries)
	metrics.ProcessConfigscanNamespaceMetrics(configScanSummaries)
}

func handleWorkloadVulnScanSummaries(storageClient *api.StorageClientImpl) {
	vulnerabilityManifestSummaries, err := storageClient.GetVulnerabilityManifestSummaries()
	if err != nil {
		logger.L().Warning("failed getting vulnerability manifest summaries", helpers.Error(err))
		return
	}
	metrics.ProcessVulnWorkloadMetrics(vulnerabilityManifestSummaries)
}

func handleVulnScanSummaries(storageClient *api.StorageClientImpl) {
	vulnScanSummaries, err := storageClient.GetVulnerabilitySummaries()
	if err != nil {
		logger.L().Warning("failed getting vulnerability scan summaries", helpers.Error(err))
		return
	}

	metrics.ProcessVulnNamespaceMetrics(vulnScanSummaries)
	metrics.ProcessVulnClusterMetrics(vulnScanSummaries)
}

// handleVulnDetailMetricsInitial loads initial per-CVE metrics by fetching each
// VulnerabilityManifestSummary individually (List strips vulnerabilitiesRef).
func handleVulnDetailMetricsInitial(storageClient *api.StorageClientImpl) {
	// List gives us the names and namespaces (severities are populated, refs are not)
	summaries, err := storageClient.GetVulnerabilityManifestSummaries()
	if err != nil {
		logger.L().Warning("failed getting vulnerability manifest summaries for initial detail load", helpers.Error(err))
		return
	}

	loaded := 0
	for _, summary := range summaries.Items {
		// Individual Get returns full object with vulnerabilitiesRef populated
		fullSummary, err := storageClient.GetVulnerabilityManifestSummary(summary.Namespace, summary.Name)
		if err != nil {
			logger.L().Debug("failed getting individual vulnerability manifest summary", helpers.String("name", summary.Name), helpers.Error(err))
			continue
		}
		metrics.ProcessVulnDetailForSummary(fullSummary, storageClient.GetManifestCached)
		loaded++
	}
	logger.L().Info("initial vulnerability detail metrics loaded", helpers.Int("summaries", loaded))
}

func parseDurationOrDefault(envVar string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(envVar)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		logger.L().Warning("failed to parse duration, using default", helpers.String("env", envVar), helpers.String("value", val), helpers.Error(err))
		return defaultVal
	}
	return d
}

func InfiniteBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
