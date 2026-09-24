package cdk_preflight

import rego.v1

# The launch template a node group uses is named by Id or by Name; both resolve
# to the logical id when they point at a template in the same stack, and the
# rule stays silent for a template that was created outside it.
_pf_ngltit_lt(name) := t if {
	t := resolve(name, "Properties.LaunchTemplate.Id")
	t in resources_of_type("AWS::EC2::LaunchTemplate")
}

_pf_ngltit_lt(name) := t if {
	t := resolve(name, "Properties.LaunchTemplate.Name")
	t in resources_of_type("AWS::EC2::LaunchTemplate")
}

violation contains make_diag_full("pf-eks-nodegroup-lt-forbids-lt-instance-type", "ERROR", name,
	"Properties.InstanceTypes",
	sprintf("InstanceTypes is set while launch template %v already sets LaunchTemplateData.InstanceType (\"Cannot specify instance types in launch template and API request\")", [ltname]),
	"Set the instance type in the launch template or in InstanceTypes, not in both",
	"https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	_pf_ekslib_has(name, "InstanceTypes")
	ltname := _pf_ngltit_lt(name)
	resolve(ltname, "Properties.LaunchTemplateData.InstanceType")
}
