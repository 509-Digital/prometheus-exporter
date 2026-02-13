package metrics

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProcessVulnWorkloadMetrics(t *testing.T) {
	vulnerabilityManifestSummaries := &v1beta1.VulnerabilityManifestSummaryList{
		Items: []v1beta1.VulnerabilityManifestSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":           "name1",
						"kubescape.io/workload-kind":           "deployment",
						"kubescape.io/workload-namespace":      "namespace1",
						"kubescape.io/workload-container-name": "container1",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 2,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      5,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      10,
							Relevant: 8,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      20,
							Relevant: 15,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":           "name2",
						"kubescape.io/workload-kind":           "deployment",
						"kubescape.io/workload-namespace":      "namespace2",
						"kubescape.io/workload-container-name": "container2",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      1,
							Relevant: 15,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      9,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 5,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      2,
							Relevant: 5,
						},
					},
				},
			},
		},
	}

	ProcessVulnWorkloadMetrics(vulnerabilityManifestSummaries)

	allCritical := &dto.Metric{}
	allHigh := &dto.Metric{}
	allMedium := &dto.Metric{}
	allLow := &dto.Metric{}
	allUnknown := &dto.Metric{}
	relevantCritical := &dto.Metric{}
	relevantHigh := &dto.Metric{}
	relevantMedium := &dto.Metric{}
	relevantLow := &dto.Metric{}
	relevantUnknown := &dto.Metric{}

	ggeWorkloadVulnCritical, _ := workloadVulnCritical.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnHigh, _ := workloadVulnHigh.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnMedium, _ := workloadVulnMedium.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnLow, _ := workloadVulnLow.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnUnknown, _ := workloadVulnUnknown.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")

	ggeWorkloadVulnCriticalRelevant, _ := workloadVulnCriticalRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnHighRelevant, _ := workloadVulnHighRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnMediumRelevant, _ := workloadVulnMediumRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnLowRelevant, _ := workloadVulnLowRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")
	ggeWorkloadVulnUnknownRelevant, _ := workloadVulnUnknownRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment", "container1")

	_ = ggeWorkloadVulnCritical.Write(allCritical)
	_ = ggeWorkloadVulnHigh.Write(allHigh)
	_ = ggeWorkloadVulnMedium.Write(allMedium)
	_ = ggeWorkloadVulnLow.Write(allLow)
	_ = ggeWorkloadVulnUnknown.Write(allUnknown)
	_ = ggeWorkloadVulnCriticalRelevant.Write(relevantCritical)
	_ = ggeWorkloadVulnHighRelevant.Write(relevantHigh)
	_ = ggeWorkloadVulnMediumRelevant.Write(relevantMedium)
	_ = ggeWorkloadVulnLowRelevant.Write(relevantLow)
	_ = ggeWorkloadVulnUnknownRelevant.Write(relevantUnknown)

	assert.Equal(t, float64(3), allCritical.Gauge.GetValue(), "Expected allCritical to be 3")
	assert.Equal(t, float64(5), allHigh.Gauge.GetValue(), "Expected allHigh to be 5")
	assert.Equal(t, float64(10), allMedium.Gauge.GetValue(), "Expected allMedium to be 10")
	assert.Equal(t, float64(20), allLow.Gauge.GetValue(), "Expected allLow to be 20")
	assert.Equal(t, float64(7), allUnknown.Gauge.GetValue(), "Expected allUnknown to be 7")
	assert.Equal(t, float64(2), relevantCritical.Gauge.GetValue(), "Expected relevantCritical to be 2")
	assert.Equal(t, float64(4), relevantHigh.Gauge.GetValue(), "Expected relevantHigh to be 4")
	assert.Equal(t, float64(8), relevantMedium.Gauge.GetValue(), "Expected relevantMedium to be 8")
	assert.Equal(t, float64(15), relevantLow.Gauge.GetValue(), "Expected relevantLow to be 15")
	assert.Equal(t, float64(3), relevantUnknown.Gauge.GetValue(), "Expected relevantUnknown to be 3")
}

func TestProcessVulnClusterMetrics(t *testing.T) {
	// Create a fake VulnerabilitySummaryList
	vulnSummary := &v1beta1.VulnerabilitySummaryList{
		Items: []v1beta1.VulnerabilitySummary{
			{
				Spec: v1beta1.VulnerabilitySummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 2,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      5,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      10,
							Relevant: 8,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      20,
							Relevant: 15,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
					},
				},
			},
			{
				Spec: v1beta1.VulnerabilitySummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      1,
							Relevant: 15,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      9,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 5,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      2,
							Relevant: 5,
						},
					},
				},
			},
		},
	}

	totalCritical, totalHigh, totalMedium, totalLow, totalUnknown, relevantCritical, relevantHigh, relevantMedium, relevantLow, relevantUnknown := ProcessVulnClusterMetrics(vulnSummary)

	assert.Equal(t, int64(4), totalCritical)
	assert.Equal(t, int64(14), totalHigh)
	assert.Equal(t, int64(13), totalMedium)
	assert.Equal(t, int64(27), totalLow)
	assert.Equal(t, int64(9), totalUnknown)
	assert.Equal(t, int64(17), relevantCritical)
	assert.Equal(t, int64(8), relevantHigh)
	assert.Equal(t, int64(13), relevantMedium)
	assert.Equal(t, int64(18), relevantLow)
	assert.Equal(t, int64(8), relevantUnknown)

}

func TestProcessConfigscanWorkloadMetrics(t *testing.T) {
	workloadConfigurationScanSummaries := &v1beta1.WorkloadConfigurationScanSummaryList{
		Items: []v1beta1.WorkloadConfigurationScanSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "name1",
						"kubescape.io/workload-kind":      "ServiceAccount",
						"kubescape.io/workload-namespace": "namespace1",
					},
				},
				Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 3,
						High:     5,
						Medium:   10,
						Low:      20,
						Unknown:  7,
					},
				},
			},
		},
	}

	ProcessConfigscanWorkloadMetrics(workloadConfigurationScanSummaries)

	critical := &dto.Metric{}
	high := &dto.Metric{}
	medium := &dto.Metric{}
	low := &dto.Metric{}
	unknown := &dto.Metric{}

	ggeWorkloadCritical, _ := workloadCritical.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadHigh, _ := workloadHigh.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadMedium, _ := workloadMedium.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadLow, _ := workloadLow.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadUnknown, _ := workloadUnknown.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")

	_ = ggeWorkloadCritical.Write(critical)
	_ = ggeWorkloadHigh.Write(high)
	_ = ggeWorkloadMedium.Write(medium)
	_ = ggeWorkloadLow.Write(low)
	_ = ggeWorkloadUnknown.Write(unknown)

	assert.Equal(t, float64(3), critical.Gauge.GetValue(), "Expected allCritical to be 3")
	assert.Equal(t, float64(5), high.Gauge.GetValue(), "Expected allHigh to be 5")
	assert.Equal(t, float64(10), medium.Gauge.GetValue(), "Expected allMedium to be 10")
	assert.Equal(t, float64(20), low.Gauge.GetValue(), "Expected allLow to be 20")
	assert.Equal(t, float64(7), unknown.Gauge.GetValue(), "Expected allUnknown to be 7")
}

func TestProcessControlDetailMetrics(t *testing.T) {
	summary := &v1beta1.WorkloadConfigurationScanSummaryList{
		Items: []v1beta1.WorkloadConfigurationScanSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "grafana",
						"kubescape.io/workload-kind":      "Deployment",
						"kubescape.io/workload-namespace": "grafana",
					},
				},
				Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 0,
						High:     2,
						Medium:   1,
					},
					Controls: map[string]v1beta1.ScannedControlSummary{
						"C-0211": {
							ControlID: "C-0211",
							Severity: v1beta1.ControlSeverity{
								Severity:    "High",
								ScoreFactor: 8,
							},
							Status: v1beta1.ScannedControlStatus{
								Status: "failed",
							},
						},
						"C-0017": {
							ControlID: "C-0017",
							Severity: v1beta1.ControlSeverity{
								Severity:    "Low",
								ScoreFactor: 3,
							},
							Status: v1beta1.ScannedControlStatus{
								Status: "passed",
							},
						},
						"C-0030": {
							ControlID: "C-0030",
							Severity: v1beta1.ControlSeverity{
								Severity:    "Medium",
								ScoreFactor: 5,
							},
							Status: v1beta1.ScannedControlStatus{
								Status: "failed",
							},
						},
					},
				},
			},
		},
	}

	ProcessControlDetailMetrics(summary)

	// Verify C-0211 is failed (value=1)
	statusMetric := &dto.Metric{}
	ggeStatus, _ := controlStatus.GetMetricWithLabelValues("grafana", "grafana", "deployment", "C-0211", "high")
	_ = ggeStatus.Write(statusMetric)
	assert.Equal(t, float64(1), statusMetric.Gauge.GetValue(), "Expected C-0211 status to be 1 (failed)")

	// Verify C-0017 is passed (value=0)
	passedMetric := &dto.Metric{}
	ggePassed, _ := controlStatus.GetMetricWithLabelValues("grafana", "grafana", "deployment", "C-0017", "low")
	_ = ggePassed.Write(passedMetric)
	assert.Equal(t, float64(0), passedMetric.Gauge.GetValue(), "Expected C-0017 status to be 0 (passed)")

	// Verify C-0030 is failed (value=1)
	failedMetric := &dto.Metric{}
	ggeFailed, _ := controlStatus.GetMetricWithLabelValues("grafana", "grafana", "deployment", "C-0030", "medium")
	_ = ggeFailed.Write(failedMetric)
	assert.Equal(t, float64(1), failedMetric.Gauge.GetValue(), "Expected C-0030 status to be 1 (failed)")

	// Verify control score for C-0211
	scoreMetric := &dto.Metric{}
	ggeScore, _ := controlScore.GetMetricWithLabelValues("C-0211", "high")
	_ = ggeScore.Write(scoreMetric)
	assert.Equal(t, float64(8), scoreMetric.Gauge.GetValue(), "Expected C-0211 score to be 8")

	// Verify control score for C-0017
	scoreMetric2 := &dto.Metric{}
	ggeScore2, _ := controlScore.GetMetricWithLabelValues("C-0017", "low")
	_ = ggeScore2.Write(scoreMetric2)
	assert.Equal(t, float64(3), scoreMetric2.Gauge.GetValue(), "Expected C-0017 score to be 3")
}

func TestDeleteControlDetailMetrics(t *testing.T) {
	// First add some metrics
	summary := &v1beta1.WorkloadConfigurationScanSummaryList{
		Items: []v1beta1.WorkloadConfigurationScanSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "test-delete",
						"kubescape.io/workload-kind":      "Deployment",
						"kubescape.io/workload-namespace": "test-ns",
					},
				},
				Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
					Controls: map[string]v1beta1.ScannedControlSummary{
						"C-0100": {
							ControlID: "C-0100",
							Severity: v1beta1.ControlSeverity{
								Severity:    "High",
								ScoreFactor: 7,
							},
							Status: v1beta1.ScannedControlStatus{
								Status: "failed",
							},
						},
					},
				},
			},
		},
	}

	ProcessControlDetailMetrics(summary)

	// Verify metric exists
	gge, err := controlStatus.GetMetricWithLabelValues("test-ns", "test-delete", "deployment", "C-0100", "high")
	assert.NoError(t, err)
	m := &dto.Metric{}
	_ = gge.Write(m)
	assert.Equal(t, float64(1), m.Gauge.GetValue())

	// Delete metrics for this workload
	DeleteControlDetailMetrics(&summary.Items[0])

	// After delete, getting the metric should return a fresh zero-value gauge
	gge2, _ := controlStatus.GetMetricWithLabelValues("test-ns", "test-delete", "deployment", "C-0100", "high")
	m2 := &dto.Metric{}
	_ = gge2.Write(m2)
	assert.Equal(t, float64(0), m2.Gauge.GetValue(), "Expected metric to be reset after delete")
}

func TestProcessConfigscanClusterMetrics(t *testing.T) {

	csSummary := &v1beta1.ConfigurationScanSummaryList{
		Items: []v1beta1.ConfigurationScanSummary{
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 8,
						High:     10,
						Medium:   7,
						Low:      8,
						Unknown:  3,
					},
				},
			},
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 7,
						High:     2,
						Medium:   1,
						Low:      3,
						Unknown:  0,
					},
				},
			},
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      6,
						Unknown:  4,
					},
				},
			},
		},
	}

	totalCritical, totalHigh, totalMedium, totalLow, totalUnknown := ProcessConfigscanClusterMetrics(csSummary)

	assert.Equal(t, int64(16), totalCritical)
	assert.Equal(t, int64(14), totalHigh)
	assert.Equal(t, int64(11), totalMedium)
	assert.Equal(t, int64(17), totalLow)
	assert.Equal(t, int64(7), totalUnknown)
}

func TestProcessVulnDetailMetrics(t *testing.T) {
	// Create summaries that reference "all" and "relevant" manifests
	summaries := &v1beta1.VulnerabilityManifestSummaryList{
		Items: []v1beta1.VulnerabilityManifestSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":           "grafana",
						"kubescape.io/workload-kind":           "Deployment",
						"kubescape.io/workload-namespace":      "grafana",
						"kubescape.io/workload-container-name": "grafana",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{All: 1, Relevant: 1},
						High:     v1beta1.VulnerabilityCounters{All: 2, Relevant: 0},
					},
					Vulnerabilities: v1beta1.VulnerabilitiesComponents{
						ImageVulnerabilitiesObj: v1beta1.VulnerabilitiesObjScope{
							Namespace: "kubescape",
							Name:      "grafana-all",
						},
						WorkloadVulnerabilitiesObj: v1beta1.VulnerabilitiesObjScope{
							Namespace: "kubescape",
							Name:      "grafana-relevant",
						},
					},
				},
			},
		},
	}

	// Create manifests: "all" has 3 CVEs, "relevant" has only 1
	manifests := &v1beta1.VulnerabilityManifestList{
		Items: []v1beta1.VulnerabilityManifest{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grafana-all",
					Namespace: "kubescape",
					Annotations: map[string]string{
						"kubescape.io/image-tag": "grafana/grafana:10.3.1",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSpec{
					Payload: v1beta1.GrypeDocument{
						Matches: []v1beta1.Match{
							{
								Vulnerability: v1beta1.Vulnerability{
									VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
										ID:       "CVE-2024-1234",
										Severity: "Critical",
										Cvss: []v1beta1.Cvss{
											{Metrics: v1beta1.CvssMetrics{BaseScore: 9.8}},
										},
									},
									Fix: v1beta1.Fix{
										Versions: []string{"3.0.14"},
										State:    "fixed",
									},
								},
								Artifact: v1beta1.GrypePackage{
									Name:    "openssl",
									Version: "3.0.1",
								},
							},
							{
								Vulnerability: v1beta1.Vulnerability{
									VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
										ID:       "CVE-2024-5678",
										Severity: "High",
										Cvss: []v1beta1.Cvss{
											{Metrics: v1beta1.CvssMetrics{BaseScore: 7.5}},
										},
									},
									Fix: v1beta1.Fix{
										State: "not-fixed",
									},
								},
								Artifact: v1beta1.GrypePackage{
									Name:    "libcurl",
									Version: "7.88.0",
								},
							},
							{
								Vulnerability: v1beta1.Vulnerability{
									VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
										ID:       "CVE-2024-9999",
										Severity: "High",
										Cvss: []v1beta1.Cvss{
											{Metrics: v1beta1.CvssMetrics{BaseScore: 8.1}},
										},
									},
									Fix: v1beta1.Fix{
										Versions: []string{"2.0.0"},
										State:    "fixed",
									},
								},
								Artifact: v1beta1.GrypePackage{
									Name:    "zlib",
									Version: "1.2.11",
								},
							},
						},
					},
				},
			},
			{
				// Relevant manifest: only CVE-2024-1234 is runtime-relevant
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grafana-relevant",
					Namespace: "kubescape",
				},
				Spec: v1beta1.VulnerabilityManifestSpec{
					Payload: v1beta1.GrypeDocument{
						Matches: []v1beta1.Match{
							{
								Vulnerability: v1beta1.Vulnerability{
									VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
										ID:       "CVE-2024-1234",
										Severity: "Critical",
									},
								},
								Artifact: v1beta1.GrypePackage{
									Name:    "openssl",
									Version: "3.0.1",
								},
							},
						},
					},
				},
			},
		},
	}

	ProcessVulnDetailMetrics(summaries, manifests)

	// Verify CVE-2024-1234 info metric
	infoMetric := &dto.Metric{}
	ggeInfo, _ := vulnerabilityInfo.GetMetricWithLabelValues(
		"CVE-2024-1234", "critical", "openssl", "3.0.1", "3.0.14", "fixed",
		"grafana", "grafana", "deployment", "grafana", "grafana/grafana:10.3.1",
	)
	_ = ggeInfo.Write(infoMetric)
	assert.Equal(t, float64(1), infoMetric.Gauge.GetValue(), "Expected vulnerability_info to be 1")

	// Verify CVE-2024-1234 CVSS score
	cvssMetric := &dto.Metric{}
	ggeCvss, _ := vulnerabilityCvss.GetMetricWithLabelValues("CVE-2024-1234", "critical", "grafana", "grafana")
	_ = ggeCvss.Write(cvssMetric)
	assert.Equal(t, float64(9.8), cvssMetric.Gauge.GetValue(), "Expected CVSS 9.8")

	// Verify CVE-2024-5678 CVSS score
	cvssMetric2 := &dto.Metric{}
	ggeCvss2, _ := vulnerabilityCvss.GetMetricWithLabelValues("CVE-2024-5678", "high", "grafana", "grafana")
	_ = ggeCvss2.Write(cvssMetric2)
	assert.Equal(t, float64(7.5), cvssMetric2.Gauge.GetValue(), "Expected CVSS 7.5")

	// Verify CVE-2024-1234 is relevant (appears in relevant manifest)
	relMetric := &dto.Metric{}
	ggeRel, _ := vulnerabilityRelevant.GetMetricWithLabelValues("CVE-2024-1234", "grafana", "grafana")
	_ = ggeRel.Write(relMetric)
	assert.Equal(t, float64(1), relMetric.Gauge.GetValue(), "Expected CVE-2024-1234 to be relevant")

	// Verify CVE-2024-5678 is NOT relevant
	notRelMetric := &dto.Metric{}
	ggeNotRel, _ := vulnerabilityRelevant.GetMetricWithLabelValues("CVE-2024-5678", "grafana", "grafana")
	_ = ggeNotRel.Write(notRelMetric)
	assert.Equal(t, float64(0), notRelMetric.Gauge.GetValue(), "Expected CVE-2024-5678 to NOT be relevant")

	// Verify CVE-2024-9999 is NOT relevant
	notRelMetric2 := &dto.Metric{}
	ggeNotRel2, _ := vulnerabilityRelevant.GetMetricWithLabelValues("CVE-2024-9999", "grafana", "grafana")
	_ = ggeNotRel2.Write(notRelMetric2)
	assert.Equal(t, float64(0), notRelMetric2.Gauge.GetValue(), "Expected CVE-2024-9999 to NOT be relevant")

	// Verify fix_state="not-fixed" for CVE-2024-5678
	noFixMetric := &dto.Metric{}
	ggeNoFix, _ := vulnerabilityInfo.GetMetricWithLabelValues(
		"CVE-2024-5678", "high", "libcurl", "7.88.0", "", "not-fixed",
		"grafana", "grafana", "deployment", "grafana", "grafana/grafana:10.3.1",
	)
	_ = ggeNoFix.Write(noFixMetric)
	assert.Equal(t, float64(1), noFixMetric.Gauge.GetValue(), "Expected vulnerability_info for unfixed CVE")
}

func TestProcessRuntimeMetrics(t *testing.T) {
	profiles := &v1beta1.ApplicationProfileList{
		Items: []v1beta1.ApplicationProfile{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "grafana",
						"kubescape.io/workload-kind":      "Deployment",
						"kubescape.io/workload-namespace": "grafana",
					},
					Annotations: map[string]string{
						"kubescape.io/status": "completed",
					},
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name:     "grafana",
							Syscalls: []string{"read", "write", "openat", "close", "mmap"},
						},
						{
							Name:     "sidecar",
							Syscalls: []string{"read", "write", "epoll_wait"},
						},
					},
				},
			},
		},
	}

	networks := &v1beta1.NetworkNeighborhoodList{
		Items: []v1beta1.NetworkNeighborhood{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "grafana",
						"kubescape.io/workload-namespace": "grafana",
					},
				},
				Spec: v1beta1.NetworkNeighborhoodSpec{
					Containers: []v1beta1.NetworkNeighborhoodContainer{
						{
							Name: "grafana",
							Ingress: []v1beta1.NetworkNeighbor{
								{Identifier: "alloy-ns/alloy"},
								{Identifier: "prometheus-ns/prometheus"},
								{Identifier: "external-client"},
							},
							Egress: []v1beta1.NetworkNeighbor{
								{Identifier: "loki-ns/loki"},
								{Identifier: "mimir-ns/mimir"},
							},
						},
					},
				},
			},
		},
	}

	ProcessRuntimeMetrics(profiles, networks)

	// Verify profile status
	statusMetric := &dto.Metric{}
	ggeStatus, _ := applicationProfileStatus.GetMetricWithLabelValues("grafana", "grafana", "deployment", "completed")
	_ = ggeStatus.Write(statusMetric)
	assert.Equal(t, float64(1), statusMetric.Gauge.GetValue(), "Expected profile status to be 1")

	// Verify syscall count for grafana container (5 syscalls)
	syscallMetric := &dto.Metric{}
	ggeSyscall, _ := applicationProfileSyscalls.GetMetricWithLabelValues("grafana", "grafana", "grafana")
	_ = ggeSyscall.Write(syscallMetric)
	assert.Equal(t, float64(5), syscallMetric.Gauge.GetValue(), "Expected 5 syscalls for grafana container")

	// Verify syscall count for sidecar container (3 syscalls)
	syscallMetric2 := &dto.Metric{}
	ggeSyscall2, _ := applicationProfileSyscalls.GetMetricWithLabelValues("grafana", "grafana", "sidecar")
	_ = ggeSyscall2.Write(syscallMetric2)
	assert.Equal(t, float64(3), syscallMetric2.Gauge.GetValue(), "Expected 3 syscalls for sidecar container")

	// Verify ingress connections (3)
	ingressMetric := &dto.Metric{}
	ggeIngress, _ := networkConnectionsTotal.GetMetricWithLabelValues("grafana", "grafana", "ingress")
	_ = ggeIngress.Write(ingressMetric)
	assert.Equal(t, float64(3), ingressMetric.Gauge.GetValue(), "Expected 3 ingress connections")

	// Verify egress connections (2)
	egressMetric := &dto.Metric{}
	ggeEgress, _ := networkConnectionsTotal.GetMetricWithLabelValues("grafana", "grafana", "egress")
	_ = ggeEgress.Write(egressMetric)
	assert.Equal(t, float64(2), egressMetric.Gauge.GetValue(), "Expected 2 egress connections")
}
