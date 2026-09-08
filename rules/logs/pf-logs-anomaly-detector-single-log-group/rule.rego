package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-anomaly-detector-single-log-group", "ERROR", name,
	"Properties.LogGroupArnList",
	sprintf("The detector lists %d log groups; CreateLogAnomalyDetector fails with \"Only 1 log group arn is supported in the list.\"", [n]),
	"Create one anomaly detector per log group",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loganomalydetector.html") if {
	some name in resources_of_type("AWS::Logs::LogAnomalyDetector")
	items := [x | some x in flatten_list(name, "Properties.LogGroupArnList")]
	n := count(items)
	n > 1
}
