package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-filter-name-charset", "ERROR", name,
	"Properties.FilterName",
	sprintf("FilterName '%s' contains a colon or asterisk; PutMetricFilter fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: [^:*]*\"", [n]),
	"Remove ':' and '*' from the filter name",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricFilter.html") if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	n := resolve(name, "Properties.FilterName")
	is_string(n)
	regex.match(`[:*]`, n)
}
