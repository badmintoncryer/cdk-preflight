package cdk_preflight

import rego.v1

# PublicAccess.Type is a free String of 7..23 characters in the schema, so SERVICE_PROVIDED_EIPS
# passes every earlier layer - but public access is an update-only switch and the create fails
# with "When creating a cluster, the only valid value for the Type parameter in PublicAccess is
# DISABLED. ... InvalidParameter: publicAccess".
violation contains make_diag_full("pf-msk-public-access-not-at-create", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type",
	sprintf("PublicAccess.Type is '%s'; the create fails with \"When creating a cluster, the only valid value for the Type parameter in PublicAccess is DISABLED\"", [t]),
	"Create the cluster with DISABLED (or no PublicAccess at all) and turn public access on afterwards",
	"https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	t := resolve(name, "Properties.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type")
	is_string(t)
	t != "DISABLED"
}
