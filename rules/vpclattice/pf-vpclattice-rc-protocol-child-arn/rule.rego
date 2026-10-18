package cdk_preflight

import rego.v1

# An ARN resource brings its own protocol and a CHILD inherits the GROUP's, so CreateResourceConfiguration rejects ProtocolType on
# these types ("Unexpected attribute ... for type ...").
violation contains make_diag_full("pf-vpclattice-rc-protocol-child-arn", "ERROR", name,
	"Properties.ProtocolType",
	sprintf("ProtocolType is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove ProtocolType; set it on the SINGLE or GROUP resource configuration",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"ARN", "CHILD"}
	_pf_vpcl_has(name, "Properties.ProtocolType")
}
