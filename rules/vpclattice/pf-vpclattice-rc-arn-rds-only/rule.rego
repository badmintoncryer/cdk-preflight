package cdk_preflight

import rego.v1

# ArnResource accepts any ARN in the schema, but the ARN type integrates RDS
# only ("ARN-based integration is only supported for RDS and not ..."). Literal
# ARNs only.
violation contains make_diag_full("pf-vpclattice-rc-arn-rds-only", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.ArnResource",
	sprintf("ArnResource is a '%s' ARN; the create fails with \"ARN-based integration is only supported for RDS\"", [p[2]]),
	"Point ArnResource at an RDS DB instance or cluster, or use a SINGLE resource configuration with the DNS name or IP address",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "ARN"
	p := _pf_vpcl_arn(resolve(name, "Properties.ResourceConfigurationDefinition.ArnResource"))
	p[2] != "rds"
}
