package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-alarm-expressions-max", "ERROR", name,
	"Properties.Metrics",
	sprintf("The alarm has %d math expressions; PutMetricAlarm fails with \"Too many expressions in alarm, maximum is 10\"", [n]),
	"Keep math expressions to 10 per alarm",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	n := count(_pf_cwlib_queries(name, "Expression"))
	n > 10
}
