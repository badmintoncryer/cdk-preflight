package cdk_preflight

import rego.v1

# MSK Serverless spreads a VPC connection over 2 to 6 subnets, each in its own Availability Zone.
# CreateClusterV2 rejects both ends with "The size of list should be between 2 and 6. ...
# InvalidParameter: subnetIds".
violation contains make_diag_full("pf-msk-serverless-subnets-count", "ERROR", name,
	sprintf("Properties.VpcConfigs[%d].SubnetIds", [it.index]),
	sprintf("VpcConfigs[%d] lists %d subnet(s); the create fails with \"The size of list should be between 2 and 6\"", [it.index, n]),
	"Give each VPC configuration between 2 and 6 subnets, one per Availability Zone",
	"https://docs.aws.amazon.com/msk/latest/developerguide/serverless.html") if {
	some name in resources_of_type("AWS::MSK::ServerlessCluster")
	some it in flatten_list(name, "Properties.VpcConfigs")
	ids := it.value.SubnetIds
	is_array(ids)
	n := count(ids)
	_pf_mskssc_out(n)
}

_pf_mskssc_out(n) if n < 2

_pf_mskssc_out(n) if n > 6
