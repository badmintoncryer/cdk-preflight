package cdk_preflight

import rego.v1

_pf_ngltsn_lt(name) := t if {
	t := resolve(name, "Properties.LaunchTemplate.Id")
	t in resources_of_type("AWS::EC2::LaunchTemplate")
}

_pf_ngltsn_lt(name) := t if {
	t := resolve(name, "Properties.LaunchTemplate.Name")
	t in resources_of_type("AWS::EC2::LaunchTemplate")
}

violation contains make_diag_full("pf-eks-nodegroup-lt-forbids-subnet-id", "ERROR", name,
	sprintf("Properties.LaunchTemplate -> %v.Properties.LaunchTemplateData.NetworkInterfaces.%v.SubnetId", [ltname, ni.index]),
	"the launch template pins SubnetId on a network interface; a managed node group takes its subnets from the node group itself (\"You must not specify a subnet in your launch template. All subnets must be specified in the API.\")",
	"Drop SubnetId from the launch template's NetworkInterfaces and list the subnets in Properties.Subnets",
	"https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	ltname := _pf_ngltsn_lt(name)
	some ni in flatten_list(ltname, "Properties.LaunchTemplateData.NetworkInterfaces")
	_pf_ekslib_ohas(ni.value, "SubnetId")
}
