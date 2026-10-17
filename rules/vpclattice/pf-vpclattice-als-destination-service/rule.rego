package cdk_preflight

import rego.v1

# DestinationArn accepts any ARN in the schema, but access logs go only to a
# CloudWatch Logs log group, an S3 bucket or a Firehose delivery stream. Any
# other service is rejected ("Destination ARN is invalid for given operation").
# Literal ARNs only.
violation contains make_diag_full("pf-vpclattice-als-destination-service", "ERROR", name,
	"Properties.DestinationArn",
	sprintf("DestinationArn is a '%s' ARN; CreateAccessLogSubscription fails with \"Destination ARN is invalid for given operation\"", [p[2]]),
	"Send access logs to a CloudWatch Logs log group, an S3 bucket or a Firehose delivery stream",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/monitoring-access-logs.html") if {
	some name in resources_of_type("AWS::VpcLattice::AccessLogSubscription")
	v := resolve(name, "Properties.DestinationArn")
	is_string(v)
	p := split(v, ":")
	count(p) >= 6
	p[0] == "arn"
	not p[2] in {"logs", "s3", "firehose"}
}
