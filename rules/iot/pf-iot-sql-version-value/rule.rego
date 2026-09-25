package cdk_preflight

import rego.v1

_pf_iotsqlver_ok := {"", "2015-10-08", "2016-03-23", "2016-03-23-beta", "beta"}

violation contains make_diag_full("pf-iot-sql-version-value", "ERROR", name,
	"Properties.TopicRulePayload.AwsIotSqlVersion",
	sprintf("AwsIotSqlVersion '%s' is not one of 2015-10-08 / 2016-03-23 / 2016-03-23-beta / beta; CreateTopicRule answers \"SqlParseException: Invalid SQL version: %s\"", [v, v]),
	"Use 2016-03-23 (the current version) or 2015-10-08",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-topicrule.html") if {
	some name in resources_of_type("AWS::IoT::TopicRule")
	v := _pf_iotlib_lit(name, "Properties.TopicRulePayload.AwsIotSqlVersion")
	not lower(v) in _pf_iotsqlver_ok
}
