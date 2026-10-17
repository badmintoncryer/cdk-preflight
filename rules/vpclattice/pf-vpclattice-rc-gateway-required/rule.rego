package cdk_preflight

import rego.v1

# SINGLE, GROUP and ARN resource configurations are reached through a resource gateway, so CreateResourceConfiguration rejects the type without ResourceGatewayId
# ("ResourceGatewayId cannot be empty"; the CFN handler checks this itself). Absence is read from the raw document,
# so a value behind Fn::If is not flagged.
violation contains make_diag_full("pf-vpclattice-rc-gateway-required", "ERROR", name,
	"Properties.ResourceConfigurationType",
	sprintf("A %s resource configuration has no ResourceGatewayId; the create fails with \"ResourceGatewayId cannot be empty\"", [t]),
	"Set ResourceGatewayId to the Id of a resource gateway (Fn::GetAtt <gateway>.Id)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"SINGLE", "GROUP", "ARN"}
	_pf_vpcl_raw(name, ["ResourceGatewayId"]) == "__pf_absent"
}
