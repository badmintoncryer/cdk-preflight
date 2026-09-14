package cdk_preflight

import rego.v1

# The source cluster may be remote; the target cluster may not. The service
# names the deploy region in the rejection, so the check is against
# data.cdk_preflight.deploy_region (enforce mode with a concrete env only).
violation contains make_diag_full("pf-msk-replicator-target-cluster-region", "ERROR", name,
	"Properties.ReplicationInfoList",
	sprintf("the target cluster is in '%s' but the replicator deploys to '%s'; the replicator create fails with \"The target cluster must be from region %s\"", [tgtRegion, region, region]),
	"Create the replicator in the target cluster's region (only the source cluster may be in another region)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-replicator.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some it in flatten_list(name, "Properties.ReplicationInfoList")
	arn := it.value.TargetKafkaClusterArn
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kafka"
	tgtRegion := parts[3]
	tgtRegion != ""
	tgtRegion != region
}
