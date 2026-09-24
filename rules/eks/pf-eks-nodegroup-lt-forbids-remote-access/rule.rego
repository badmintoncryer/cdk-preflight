package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-lt-forbids-remote-access", "ERROR", name,
	"Properties.RemoteAccess",
	"RemoteAccess is set alongside LaunchTemplate; SSH access has to come from the launch template (\"Remote access configuration cannot be specified with a launch template.\")",
	"Drop RemoteAccess and set KeyName / security groups in the launch template",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	_pf_ekslib_has(name, "LaunchTemplate")
	_pf_ekslib_has(name, "RemoteAccess")
}
