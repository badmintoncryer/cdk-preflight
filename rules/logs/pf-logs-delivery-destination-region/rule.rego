package cdk_preflight

import rego.v1

# Needs the deploy environment (enforce mode only). S3 ARNs carry an empty
# region segment and are skipped.
violation contains make_diag_full("pf-logs-delivery-destination-region", "ERROR", name,
	"Properties.DestinationResourceArn",
	sprintf("The destination ARN names region %s but the stack deploys to %s; PutDeliveryDestination fails with \"Region from identity does not match the Destination Resource ARN.\"", [arn_region, region]),
	"Build the ARN with ${AWS::Region}, or deploy the delivery destination from the region that holds the target",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDeliveryDestination.html") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::Logs::DeliveryDestination")
	parts := _pf_lglib_arn(resolve(name, "Properties.DestinationResourceArn"))
	arn_region := parts[3]
	arn_region != ""
	arn_region != region
}
