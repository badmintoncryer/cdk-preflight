package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-namespace-colon", "ERROR", name,
	"Properties.SingleMetricAnomalyDetector.Namespace",
	sprintf("Namespace '%s' starts with a colon; PutAnomalyDetector fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: [^:].*\"", [ns]),
	"Start the namespace with any character other than a colon",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	ns := resolve(name, "Properties.SingleMetricAnomalyDetector.Namespace")
	is_string(ns)
	startswith(ns, ":")
}
