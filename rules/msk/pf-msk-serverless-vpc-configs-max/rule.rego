package cdk_preflight

import rego.v1

# MSK Serverless attaches to at most 5 VPCs. CreateClusterV2 rejects a sixth with "The size of list
# should be between 1 and 5. ... InvalidParameter: vpcConfigs". (The lower end is the schema's job.)
violation contains make_diag_full("pf-msk-serverless-vpc-configs-max", "ERROR", name,
	"Properties.VpcConfigs",
	sprintf("VpcConfigs lists %d VPC configurations; the create fails with \"The size of list should be between 1 and 5\"", [n]),
	"Attach the serverless cluster to at most 5 VPCs",
	"https://docs.aws.amazon.com/msk/latest/developerguide/serverless.html") if {
	some name in resources_of_type("AWS::MSK::ServerlessCluster")
	cfgs := flatten_list(name, "Properties.VpcConfigs")
	n := count(cfgs)
	n > 5
}
