package metrics

import (
	"os"
	"strings"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	workloadCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_critical",
		Help: "Total number of critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_high",
		Help: "Total number of high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_medium",
		Help: "Total number of medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_low",
		Help: "Total number of low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	workloadUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_workload_unknown",
		Help: "Total number of unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind"})

	namespaceCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	}, []string{"namespace"})
	clusterCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	clusterHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	clusterMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	clusterLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	clusterUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_controls_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})

	workloadVulnCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_critical",
		Help: "Total number of critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_high",
		Help: "Total number of high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_medium",
		Help: "Total number of medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_low",
		Help: "Total number of low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_workload_unknown",
		Help: "Total number of unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	namespaceVulnCritical = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_critical",
		Help: "Total number of critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnHigh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_high",
		Help: "Total number of high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnMedium = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_medium",
		Help: "Total number of medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnLow = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_low",
		Help: "Total number of low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnUnknown = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_namespace_unknown",
		Help: "Total number of unknown vulnerabilities in the namespace",
	}, []string{"namespace"})
	clusterVulnCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	clusterVulnHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	clusterVulnMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	clusterVulnLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	clusterVulnUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})

	workloadVulnCriticalRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_critical",
		Help: "Number of relevant critical vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnHighRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_high",
		Help: "Number of relevant high vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnMediumRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_medium",
		Help: "Number of relevant medium vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnLowRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_low",
		Help: "Number of relevant low vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	workloadVulnUnknownRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_workload_unknown",
		Help: "Number of relevant unknown vulnerabilities in the workload",
	}, []string{"namespace", "workload", "workload_kind", "workload_container_name"})

	namespaceVulnCriticalRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_critical",
		Help: "Number of relevant critical vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnHighRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_high",
		Help: "Number of relevant high vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnMediumRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_medium",
		Help: "Number of relevant medium vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnLowRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_low",
		Help: "Number of relevant low vulnerabilities in the namespace",
	}, []string{"namespace"})

	namespaceVulnUnknownRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_namespace_unknown",
		Help: "Number of relevant unknown vulnerabilities in the namespace",
	}, []string{"namespace"})

	clusterVulnCriticalRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_critical",
		Help: "Number of relevant critical vulnerabilities in the cluster",
	})

	clusterVulnHighRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_high",
		Help: "Number of relevant high vulnerabilities in the cluster",
	})

	clusterVulnMediumRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_medium",
		Help: "Number of relevant medium vulnerabilities in the cluster",
	})

	clusterVulnLowRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_low",
		Help: "Number of relevant low vulnerabilities in the cluster",
	})

	clusterVulnUnknownRelevant = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_relevant_cluster_unknown",
		Help: "Number of relevant unknown vulnerabilities in the cluster",
	})

	// Per-control detail metrics (Tier 2)
	controlStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_control_status",
		Help: "Control compliance status per workload (1=failed, 0=passed)",
	}, []string{"namespace", "workload", "workload_kind", "control_id", "severity"})

	controlScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_control_score",
		Help: "Control severity score factor (0-10)",
	}, []string{"control_id", "severity"})

	// Per-CVE vulnerability detail metrics (Tier 1)
	vulnerabilityInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerability_info",
		Help: "Vulnerability info per workload (value=1)",
	}, []string{"vuln_id", "severity", "package", "installed_version", "fixed_version", "fix_state", "namespace", "workload", "workload_kind", "container", "image"})

	vulnerabilityCvss = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerability_cvss",
		Help: "Vulnerability CVSS base score",
	}, []string{"vuln_id", "severity", "namespace", "workload"})

	vulnerabilityRelevant = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_vulnerability_relevant",
		Help: "Vulnerability runtime relevancy (1=relevant, 0=not relevant)",
	}, []string{"vuln_id", "namespace", "workload"})

	// Runtime security metrics (Tier 3)
	applicationProfileStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_application_profile_status",
		Help: "Application profile learning status (value=1)",
	}, []string{"namespace", "workload", "workload_kind", "status"})

	applicationProfileSyscalls = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_application_profile_syscalls",
		Help: "Number of unique syscalls observed per container",
	}, []string{"namespace", "workload", "container"})

	networkConnectionsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubescape_network_connections_total",
		Help: "Number of observed network connections per workload",
	}, []string{"namespace", "workload", "direction"})
)

func init() {
	if os.Getenv("ENABLE_WORKLOAD_METRICS") == "true" {
		prometheus.MustRegister(workloadCritical)
		prometheus.MustRegister(workloadHigh)
		prometheus.MustRegister(workloadMedium)
		prometheus.MustRegister(workloadLow)
		prometheus.MustRegister(workloadUnknown)
		prometheus.MustRegister(workloadVulnCritical)
		prometheus.MustRegister(workloadVulnHigh)
		prometheus.MustRegister(workloadVulnMedium)
		prometheus.MustRegister(workloadVulnLow)
		prometheus.MustRegister(workloadVulnUnknown)
		prometheus.MustRegister(workloadVulnCriticalRelevant)
		prometheus.MustRegister(workloadVulnHighRelevant)
		prometheus.MustRegister(workloadVulnMediumRelevant)
		prometheus.MustRegister(workloadVulnLowRelevant)
		prometheus.MustRegister(workloadVulnUnknownRelevant)
	}
	if os.Getenv("ENABLE_CONTROL_DETAIL") != "false" {
		prometheus.MustRegister(controlStatus)
		prometheus.MustRegister(controlScore)
	}
	if os.Getenv("ENABLE_VULNERABILITY_DETAIL") != "false" {
		prometheus.MustRegister(vulnerabilityInfo)
		prometheus.MustRegister(vulnerabilityCvss)
		prometheus.MustRegister(vulnerabilityRelevant)
	}
	if os.Getenv("ENABLE_RUNTIME_METRICS") != "false" {
		prometheus.MustRegister(applicationProfileStatus)
		prometheus.MustRegister(applicationProfileSyscalls)
		prometheus.MustRegister(networkConnectionsTotal)
	}
	prometheus.MustRegister(namespaceCritical)
	prometheus.MustRegister(namespaceHigh)
	prometheus.MustRegister(namespaceMedium)
	prometheus.MustRegister(namespaceLow)
	prometheus.MustRegister(namespaceUnknown)
	prometheus.MustRegister(clusterCritical)
	prometheus.MustRegister(clusterHigh)
	prometheus.MustRegister(clusterMedium)
	prometheus.MustRegister(clusterLow)
	prometheus.MustRegister(clusterUnknown)
	prometheus.MustRegister(namespaceVulnCritical)
	prometheus.MustRegister(namespaceVulnHigh)
	prometheus.MustRegister(namespaceVulnMedium)
	prometheus.MustRegister(namespaceVulnLow)
	prometheus.MustRegister(namespaceVulnUnknown)
	prometheus.MustRegister(clusterVulnCritical)
	prometheus.MustRegister(clusterVulnHigh)
	prometheus.MustRegister(clusterVulnMedium)
	prometheus.MustRegister(clusterVulnLow)
	prometheus.MustRegister(clusterVulnUnknown)
	prometheus.MustRegister(namespaceVulnCriticalRelevant)
	prometheus.MustRegister(namespaceVulnHighRelevant)
	prometheus.MustRegister(namespaceVulnMediumRelevant)
	prometheus.MustRegister(namespaceVulnLowRelevant)
	prometheus.MustRegister(namespaceVulnUnknownRelevant)
	prometheus.MustRegister(clusterVulnCriticalRelevant)
	prometheus.MustRegister(clusterVulnHighRelevant)
	prometheus.MustRegister(clusterVulnMediumRelevant)
	prometheus.MustRegister(clusterVulnLowRelevant)
	prometheus.MustRegister(clusterVulnUnknownRelevant)
}

func ProcessConfigscanWorkloadMetrics(summary *v1beta1.WorkloadConfigurationScanSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
		workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
		kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])

		workloadCritical.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Critical))
		workloadHigh.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.High))
		workloadLow.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Low))
		workloadMedium.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Medium))
		workloadUnknown.WithLabelValues(namespace, workload, kind).Set(float64(item.Spec.Severities.Unknown))
	}
}

func DeleteConfigscanWorkloadMetric(item *v1beta1.WorkloadConfigurationScanSummary) {
	namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
	kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])

	workloadCritical.DeleteLabelValues(namespace, workload, kind)
	workloadHigh.DeleteLabelValues(namespace, workload, kind)
	workloadMedium.DeleteLabelValues(namespace, workload, kind)
	workloadLow.DeleteLabelValues(namespace, workload, kind)
	workloadUnknown.DeleteLabelValues(namespace, workload, kind)
}

func ProcessConfigscanNamespaceMetrics(summary *v1beta1.ConfigurationScanSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Name
		namespaceCritical.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical))
		namespaceHigh.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High))
		namespaceLow.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low))
		namespaceMedium.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium))
		namespaceUnknown.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown))
	}
}

func ProcessConfigscanClusterMetrics(summary *v1beta1.ConfigurationScanSummaryList) (totalCritical, totalHigh, totalLow, totalMedium, totalUnknown int64) {

	for _, item := range summary.Items {
		totalCritical += item.Spec.Severities.Critical
		totalHigh += item.Spec.Severities.High
		totalMedium += item.Spec.Severities.Medium
		totalLow += item.Spec.Severities.Low
		totalUnknown += item.Spec.Severities.Unknown
	}

	clusterCritical.Set(float64(totalCritical))
	clusterHigh.Set(float64(totalHigh))
	clusterLow.Set(float64(totalLow))
	clusterMedium.Set(float64(totalMedium))
	clusterUnknown.Set(float64(totalUnknown))

	return totalCritical, totalHigh, totalMedium, totalLow, totalUnknown
}

func ProcessVulnWorkloadMetrics(summary *v1beta1.VulnerabilityManifestSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
		workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
		kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])
		containerName := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-container-name"])

		workloadVulnCritical.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Critical.All))
		workloadVulnHigh.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.High.All))
		workloadVulnMedium.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Medium.All))
		workloadVulnLow.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Low.All))
		workloadVulnUnknown.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Unknown.All))
		workloadVulnCriticalRelevant.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Critical.Relevant))
		workloadVulnHighRelevant.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.High.Relevant))
		workloadVulnMediumRelevant.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Medium.Relevant))
		workloadVulnLowRelevant.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Low.Relevant))
		workloadVulnUnknownRelevant.WithLabelValues(namespace, workload, kind, containerName).Set(float64(item.Spec.Severities.Unknown.Relevant))
	}
}

func DeleteVulnWorkloadMetric(item *v1beta1.VulnerabilityManifestSummary) {
	namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
	kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])
	containerName := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-container-name"])

	workloadVulnCritical.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnHigh.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnMedium.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnLow.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnUnknown.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnCriticalRelevant.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnHighRelevant.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnMediumRelevant.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnLowRelevant.DeleteLabelValues(namespace, workload, kind, containerName)
	workloadVulnUnknownRelevant.DeleteLabelValues(namespace, workload, kind, containerName)
}

func ProcessVulnNamespaceMetrics(summary *v1beta1.VulnerabilitySummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Name
		namespaceVulnCritical.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical.All))
		namespaceVulnHigh.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High.All))
		namespaceVulnLow.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low.All))
		namespaceVulnMedium.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium.All))
		namespaceVulnUnknown.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown.All))
		namespaceVulnCriticalRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Critical.Relevant))
		namespaceVulnHighRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.High.Relevant))
		namespaceVulnLowRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Low.Relevant))
		namespaceVulnMediumRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Medium.Relevant))
		namespaceVulnUnknownRelevant.WithLabelValues(namespace).Set(float64(item.Spec.Severities.Unknown.Relevant))
	}
}

func ProcessVulnClusterMetrics(summary *v1beta1.VulnerabilitySummaryList) (totalCritical, totalHigh, totalLow, totalMedium, totalUnknown, relevantCritical, relevantHigh, relevantLow, relevantMedium, relevantUnknown int64) {

	for _, item := range summary.Items {
		totalCritical += item.Spec.Severities.Critical.All
		totalHigh += item.Spec.Severities.High.All
		totalMedium += item.Spec.Severities.Medium.All
		totalLow += item.Spec.Severities.Low.All
		totalUnknown += item.Spec.Severities.Unknown.All

		relevantCritical += item.Spec.Severities.Critical.Relevant
		relevantHigh += item.Spec.Severities.High.Relevant
		relevantMedium += item.Spec.Severities.Medium.Relevant
		relevantLow += item.Spec.Severities.Low.Relevant
		relevantUnknown += item.Spec.Severities.Unknown.Relevant
	}

	clusterVulnCritical.Set(float64(totalCritical))
	clusterVulnHigh.Set(float64(totalHigh))
	clusterVulnMedium.Set(float64(totalMedium))
	clusterVulnLow.Set(float64(totalLow))
	clusterVulnUnknown.Set(float64(totalUnknown))
	clusterVulnCriticalRelevant.Set(float64(relevantCritical))
	clusterVulnHighRelevant.Set(float64(relevantHigh))
	clusterVulnMediumRelevant.Set(float64(relevantMedium))
	clusterVulnLowRelevant.Set(float64(relevantLow))
	clusterVulnUnknownRelevant.Set(float64(relevantUnknown))

	return totalCritical, totalHigh, totalMedium, totalLow, totalUnknown, relevantCritical, relevantHigh, relevantMedium, relevantLow, relevantUnknown
}

// ProcessControlDetailMetrics extracts per-control pass/fail status from the
// Controls map in WorkloadConfigurationScanSummary objects. This provides
// granular visibility into which specific security controls are failing on
// which workloads, enabling drill-down dashboards in Grafana.
func ProcessControlDetailMetrics(summary *v1beta1.WorkloadConfigurationScanSummaryList) {
	for _, item := range summary.Items {
		namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
		workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
		kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])

		for _, ctrl := range item.Spec.Controls {
			severity := strings.ToLower(ctrl.Severity.Severity)
			var statusVal float64
			if ctrl.Status.Status == "failed" {
				statusVal = 1
			}
			controlStatus.WithLabelValues(namespace, workload, kind, ctrl.ControlID, severity).Set(statusVal)
			controlScore.WithLabelValues(ctrl.ControlID, severity).Set(float64(ctrl.Severity.ScoreFactor))
		}
	}
}

// DeleteControlDetailMetrics removes all per-control metrics for a workload
// using partial label match on namespace, workload, and kind.
func DeleteControlDetailMetrics(item *v1beta1.WorkloadConfigurationScanSummary) {
	namespace := item.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := item.ObjectMeta.Labels["kubescape.io/workload-name"]
	kind := strings.ToLower(item.ObjectMeta.Labels["kubescape.io/workload-kind"])

	controlStatus.DeletePartialMatch(prometheus.Labels{
		"namespace":     namespace,
		"workload":      workload,
		"workload_kind": kind,
	})
}

// ManifestGetter is a function that retrieves a VulnerabilityManifest by namespace and name.
// Used to decouple metrics processing from the API client, enabling unit tests with mock getters.
type ManifestGetter func(namespace, name string) (*v1beta1.VulnerabilityManifest, error)

// ProcessVulnDetailForSummary processes per-CVE vulnerability metrics for a single
// VulnerabilityManifestSummary. It uses the summary's vulnerabilitiesRef to fetch
// the "all" and "relevant" manifests via getManifest (which should be cache-backed).
func ProcessVulnDetailForSummary(summary *v1beta1.VulnerabilityManifestSummary, getManifest ManifestGetter) {
	namespace := summary.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := summary.ObjectMeta.Labels["kubescape.io/workload-name"]
	kind := strings.ToLower(summary.ObjectMeta.Labels["kubescape.io/workload-kind"])
	container := strings.ToLower(summary.ObjectMeta.Labels["kubescape.io/workload-container-name"])

	// Look up the "all" manifest via its ref
	allRef := summary.Spec.Vulnerabilities.ImageVulnerabilitiesObj
	if allRef.Name == "" {
		return
	}
	allManifest, err := getManifest(allRef.Namespace, allRef.Name)
	if err != nil || allManifest == nil {
		return
	}

	// Extract image tag from manifest annotations
	image := allManifest.Annotations["kubescape.io/image-tag"]

	// Build set of relevant CVE IDs from the "relevant" manifest
	relevantCVEs := make(map[string]struct{})
	relRef := summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj
	if relRef.Name != "" {
		if relManifest, err := getManifest(relRef.Namespace, relRef.Name); err == nil && relManifest != nil {
			for _, match := range relManifest.Spec.Payload.Matches {
				relevantCVEs[match.Vulnerability.ID] = struct{}{}
			}
		}
	}

	// Emit metrics for each CVE in the "all" manifest
	for _, match := range allManifest.Spec.Payload.Matches {
		vulnID := match.Vulnerability.ID
		severity := strings.ToLower(match.Vulnerability.Severity)
		pkg := match.Artifact.Name
		installedVersion := match.Artifact.Version
		fixState := match.Vulnerability.Fix.State
		fixVersion := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixVersion = match.Vulnerability.Fix.Versions[0]
		}

		vulnerabilityInfo.WithLabelValues(
			vulnID, severity, pkg, installedVersion, fixVersion, fixState,
			namespace, workload, kind, container, image,
		).Set(1)

		// CVSS base score
		var baseScore float64
		if len(match.Vulnerability.Cvss) > 0 {
			baseScore = match.Vulnerability.Cvss[0].Metrics.BaseScore
		}
		vulnerabilityCvss.WithLabelValues(vulnID, severity, namespace, workload).Set(baseScore)

		// Relevancy
		var relevantVal float64
		if _, isRelevant := relevantCVEs[vulnID]; isRelevant {
			relevantVal = 1
		}
		vulnerabilityRelevant.WithLabelValues(vulnID, namespace, workload).Set(relevantVal)
	}
}

// DeleteVulnDetailForSummary removes all per-CVE metrics for a workload
// using partial label match on namespace and workload.
func DeleteVulnDetailForSummary(summary *v1beta1.VulnerabilityManifestSummary) {
	namespace := summary.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := summary.ObjectMeta.Labels["kubescape.io/workload-name"]

	labels := prometheus.Labels{
		"namespace": namespace,
		"workload":  workload,
	}
	vulnerabilityInfo.DeletePartialMatch(labels)
	vulnerabilityCvss.DeletePartialMatch(labels)
	vulnerabilityRelevant.DeletePartialMatch(labels)
}

// ProcessRuntimeMetricsForProfile processes runtime metrics for a single ApplicationProfile.
func ProcessRuntimeMetricsForProfile(profile *v1beta1.ApplicationProfile) {
	namespace := profile.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := profile.ObjectMeta.Labels["kubescape.io/workload-name"]
	kind := strings.ToLower(profile.ObjectMeta.Labels["kubescape.io/workload-kind"])

	// Derive status from annotations
	status := "unknown"
	if s, ok := profile.ObjectMeta.Annotations["kubescape.io/status"]; ok && s != "" {
		status = s
	}

	applicationProfileStatus.WithLabelValues(namespace, workload, kind, status).Set(1)

	// Syscall counts per container
	for _, c := range profile.Spec.Containers {
		applicationProfileSyscalls.WithLabelValues(namespace, workload, c.Name).Set(float64(len(c.Syscalls)))
	}
	for _, c := range profile.Spec.InitContainers {
		applicationProfileSyscalls.WithLabelValues(namespace, workload, c.Name).Set(float64(len(c.Syscalls)))
	}
}

// DeleteRuntimeMetricsForProfile removes all runtime metrics for an ApplicationProfile's workload.
func DeleteRuntimeMetricsForProfile(profile *v1beta1.ApplicationProfile) {
	namespace := profile.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := profile.ObjectMeta.Labels["kubescape.io/workload-name"]

	labels := prometheus.Labels{
		"namespace": namespace,
		"workload":  workload,
	}
	applicationProfileStatus.DeletePartialMatch(labels)
	applicationProfileSyscalls.DeletePartialMatch(labels)
}

// ProcessRuntimeMetricsForNetwork processes runtime metrics for a single NetworkNeighborhood.
func ProcessRuntimeMetricsForNetwork(network *v1beta1.NetworkNeighborhood) {
	namespace := network.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := network.ObjectMeta.Labels["kubescape.io/workload-name"]

	var ingressCount, egressCount int
	for _, c := range network.Spec.Containers {
		ingressCount += len(c.Ingress)
		egressCount += len(c.Egress)
	}
	for _, c := range network.Spec.InitContainers {
		ingressCount += len(c.Ingress)
		egressCount += len(c.Egress)
	}

	networkConnectionsTotal.WithLabelValues(namespace, workload, "ingress").Set(float64(ingressCount))
	networkConnectionsTotal.WithLabelValues(namespace, workload, "egress").Set(float64(egressCount))
}

// DeleteRuntimeMetricsForNetwork removes all network connection metrics for a NetworkNeighborhood's workload.
func DeleteRuntimeMetricsForNetwork(network *v1beta1.NetworkNeighborhood) {
	namespace := network.ObjectMeta.Labels["kubescape.io/workload-namespace"]
	workload := network.ObjectMeta.Labels["kubescape.io/workload-name"]

	networkConnectionsTotal.DeletePartialMatch(prometheus.Labels{
		"namespace": namespace,
		"workload":  workload,
	})
}
