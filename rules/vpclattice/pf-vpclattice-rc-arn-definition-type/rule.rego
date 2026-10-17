package cdk_preflight

import rego.v1

# An ARN resource configuration points at an AWS resource by its ARN, so its
# definition must be an ArnResource; an IpResource, DnsResource or CidrResource
# is rejected ("ARN resource required when the type is ARN").
violation contains make_diag_full("pf-vpclattice-rc-arn-definition-type", "ERROR", name,
	sprintf("Properties.ResourceConfigurationDefinition.%s", [k]),
	sprintf("An ARN resource configuration is defined by %s; the create fails with \"ARN resource required when the type is ARN\"", [k]),
	"Use ArnResource with the ARN of the resource (an RDS DB instance or cluster)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "ARN"
	some k in ["IpResource", "DnsResource", "CidrResource"]
	_pf_vpcl_has(name, sprintf("Properties.ResourceConfigurationDefinition.%s", [k]))
}
