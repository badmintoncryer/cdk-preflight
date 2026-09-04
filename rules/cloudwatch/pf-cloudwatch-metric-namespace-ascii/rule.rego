package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-metric-namespace-ascii", "ERROR", name,
	"Properties.Namespace",
	sprintf("Namespace '%s' contains non-ASCII characters; CloudWatch rejects the alarm with \"Namespace must not contain Non-ASCII characters.\"", [ns]),
	"Use ASCII only in the metric namespace",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	ns := resolve(name, "Properties.Namespace")
	is_string(ns)
	not regex.match(`^[\x00-\x7f]*$`, ns)
}
