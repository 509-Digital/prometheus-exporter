package api

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type StorageClient interface {
	GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error)
	GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error)
	GetVulnerabilityManifests() (*v1beta1.VulnerabilityManifestList, error)
	GetApplicationProfiles() (*v1beta1.ApplicationProfileList, error)
	GetNetworkNeighborhoods() (*v1beta1.NetworkNeighborhoodList, error)
}
