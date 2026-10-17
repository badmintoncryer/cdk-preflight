package cdk_preflight

import rego.v1

# A CHILD is associated through its GROUP, so CreateResourceConfiguration rejects AllowAssociationToSharableServiceNetwork on
# these types ("Unexpected attribute ... for type ..."). Any value is flagged, false included.
violation contains make_diag_full("pf-vpclattice-rc-allow-sharable-child", "ERROR", name,
	"Properties.AllowAssociationToSharableServiceNetwork",
	sprintf("AllowAssociationToSharableServiceNetwork is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove AllowAssociationToSharableServiceNetwork from the CHILD; set it on the GROUP",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"CHILD"}
	_pf_vpcl_has(name, "Properties.AllowAssociationToSharableServiceNetwork")
}
