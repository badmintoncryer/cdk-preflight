package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-metric-stream-filters-exclusive", "ERROR", name,
	"Properties.ExcludeFilters",
	"The metric stream sets both IncludeFilters and ExcludeFilters; PutMetricStream fails with \"IncludeFilters and ExcludeFilters cannot both be present\"",
	"Keep one list: an allowlist (IncludeFilters) or a denylist (ExcludeFilters)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	not _pf_cwlib_absent(name, "IncludeFilters")
	not _pf_cwlib_absent(name, "ExcludeFilters")
}
