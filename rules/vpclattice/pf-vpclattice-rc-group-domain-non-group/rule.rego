package cdk_preflight

import rego.v1

# GroupDomain is the parent domain of a GROUP's members, so CreateResourceConfiguration rejects GroupDomain on
# these types ("GroupDomain is only allowed for GROUP type"; the CFN handler checks this itself).
violation contains make_diag_full("pf-vpclattice-rc-group-domain-non-group", "ERROR", name,
	"Properties.GroupDomain",
	sprintf("GroupDomain is set on a %s resource configuration; the create fails with \"GroupDomain is only allowed for GROUP type\"", [t]),
	"Remove GroupDomain, or set it on the GROUP resource configuration",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"SINGLE", "CHILD", "ARN"}
	_pf_vpcl_has(name, "Properties.GroupDomain")
}
