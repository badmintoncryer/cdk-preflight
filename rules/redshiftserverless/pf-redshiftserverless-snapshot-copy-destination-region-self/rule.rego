package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is defined only when the enforce plugin knows the
# app's concrete region (see src/private/enforce.ts); without it the reference is
# undefined and this rule skips. resolve() flattens Ref AWS::Region, so a copy aimed at
# the pseudo parameter is caught as well as a literal.
violation contains make_diag_full("pf-redshiftserverless-snapshot-copy-destination-region-self", "ERROR", name,
	sprintf("Properties.SnapshotCopyConfigurations.%d.DestinationRegion", [i]),
	sprintf("DestinationRegion %s is the region the namespace itself deploys to; the copy configuration fails with \"Invalid Region '%s'.\"", [r, r]),
	"Point the snapshot copy at a different region, or drop the SnapshotCopyConfigurations entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshiftserverless-namespace.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arr := object.get(_pf_rsslib_props(name), "SnapshotCopyConfigurations", [])
	is_array(arr)
	some i, _ in arr
	r := resolve(name, sprintf("Properties.SnapshotCopyConfigurations.%d.DestinationRegion", [i]))
	r == region
}
