package cdk_preflight

import rego.v1

# The property name says stream, and a log-group ARN is the natural mistake
# (that is what CDK's LogGroup.logGroupArn hands you).
violation contains make_diag_full("pf-kinesisanalytics-log-stream-arn", "ERROR", name,
	"Properties.CloudWatchLoggingOption.LogStreamARN",
	sprintf("'%v' is a log-group ARN; CreateApplication fails with \"CloudWatch log stream ARN ... is invalid.\"", [arn]),
	"Use the log stream ARN (.../log-group:<group>:log-stream:<stream>)",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CloudWatchLoggingOption.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::ApplicationCloudWatchLoggingOption")
	arn := resolve(name, "Properties.CloudWatchLoggingOption.LogStreamARN")
	_pf_kinlib_arn_region(arn, "logs")
	indexof(arn, ":log-stream:") == -1
}
