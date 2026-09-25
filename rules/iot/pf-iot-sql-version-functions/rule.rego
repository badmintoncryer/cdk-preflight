package cdk_preflight

import rego.v1

_pf_iotsqlfn_v1(name) if not resolve(name, "Properties.TopicRulePayload.AwsIotSqlVersion")

_pf_iotsqlfn_v1(name) if _pf_iotlib_lit(name, "Properties.TopicRulePayload.AwsIotSqlVersion") == "2015-10-08"

violation contains make_diag_full("pf-iot-sql-version-functions", "ERROR", name,
	"Properties.TopicRulePayload.Sql",
	"the statement calls encode(), which SQL version 2015-10-08 (the default when AwsIotSqlVersion is omitted) does not have; CreateTopicRule answers \"ERROR: Function 'encode' is only supported in sql version 2016-03-23-beta and above.\"",
	"Set AwsIotSqlVersion to 2016-03-23",
	"https://docs.aws.amazon.com/iot/latest/developerguide/iot-sql-functions.html") if {
	some name in resources_of_type("AWS::IoT::TopicRule")
	regex.match(`(?i)\bencode\s*\(`, _pf_iotlib_sql(name))
	_pf_iotsqlfn_v1(name)
}
