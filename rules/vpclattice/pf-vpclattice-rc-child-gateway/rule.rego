package cdk_preflight

import rego.v1

# A CHILD inherits the resource gateway of its GROUP, so CreateResourceConfiguration rejects ResourceGatewayId on
# these types ("Unexpected attribute ... for type ...").
violation contains make_diag_full("pf-vpclattice-rc-child-gateway", "ERROR", name,
	"Properties.ResourceGatewayId",
	sprintf("ResourceGatewayId is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove ResourceGatewayId from the CHILD; set it on the GROUP",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"CHILD"}
	_pf_vpcl_has(name, "Properties.ResourceGatewayId")
}
