package cdk_preflight

import rego.v1

# The ports of an ARN resource come from the resource itself, so CreateResourceConfiguration rejects PortRanges on
# these types ("Unexpected attribute ... for type ...").
violation contains make_diag_full("pf-vpclattice-rc-arn-port-ranges", "ERROR", name,
	"Properties.PortRanges",
	sprintf("PortRanges is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove PortRanges from the ARN resource configuration",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"ARN"}
	_pf_vpcl_has(name, "Properties.PortRanges")
}
