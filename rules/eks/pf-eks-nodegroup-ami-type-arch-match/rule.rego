package cdk_preflight

import rego.v1

# AmiType spells the architecture out: every managed value carries either
# ARM_64 or x86_64 (CUSTOM carries neither and the rule skips it).
_pf_ngarch_ami(at) := "arm64" if contains(at, "ARM_64")

_pf_ngarch_ami(at) := "x86_64" if contains(at, "x86_64")

# Graviton families are the ones whose generation digits are followed by a "g"
# (m6g, c7gn, im4gn, x2gd, g5g, hpc7g …), plus the first-generation a1. Every
# x86 family either has no letter after the digits (m5, c6i) or starts with a
# different one (g4dn, p4d, i3en), so the same test keeps them out.
_pf_ngarch_type(it) := "arm64" if {
	family := split(it, ".")[0]
	family == "a1"
}

_pf_ngarch_type(it) := "arm64" if {
	family := split(it, ".")[0]
	regex.match(`^[a-z]+[0-9]+g[a-z]*$`, family)
}

_pf_ngarch_type(it) := "x86_64" if {
	family := split(it, ".")[0]
	family != "a1"
	not regex.match(`^[a-z]+[0-9]+g[a-z]*$`, family)
	regex.match(`^[a-z]+[0-9]+[a-z]*$`, family)
}

violation contains make_diag_full("pf-eks-nodegroup-ami-type-arch-match", "ERROR", name,
	sprintf("Properties.InstanceTypes.%v", [it.index]),
	sprintf("instance type %v is %v but AmiType %v is %v (\"[%v] is not a valid instance type for requested amiType %v\")", [it.value, itarch, at, amiarch, it.value, at]),
	"Pick an instance type whose architecture matches AmiType, or switch AmiType to the matching architecture",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	at := resolve(name, "Properties.AmiType")
	amiarch := _pf_ngarch_ami(at)
	some it in flatten_list(name, "Properties.InstanceTypes")
	_pf_ekslib_lit(it.value)
	itarch := _pf_ngarch_type(it.value)
	itarch != amiarch
}
