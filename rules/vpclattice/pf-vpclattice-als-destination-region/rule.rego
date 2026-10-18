package cdk_preflight

import rego.v1

# A log group or delivery stream in another region is rejected ("Provided
# destinationArn is for wrong region. Expected us-east-1 but was ..."). S3 ARNs
# carry no region and are not checked. data.cdk_preflight.deploy_region is
# defined only in enforce mode with a concrete region, otherwise this rule
# skips. Literal ARNs only.
violation contains make_diag_full("pf-vpclattice-als-destination-region", "ERROR", name,
	"Properties.DestinationArn",
	sprintf("The destination is in '%s' but the stack deploys to '%s'; CreateAccessLogSubscription fails with \"Provided destinationArn is for wrong region\"", [p[3], region]),
	"Create the log group or delivery stream in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/monitoring-access-logs.html") if {
	some name in resources_of_type("AWS::VpcLattice::AccessLogSubscription")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	p := _pf_vpcl_arn(resolve(name, "Properties.DestinationArn"))
	p[2] in {"logs", "firehose"}
	p[3] != region
}
