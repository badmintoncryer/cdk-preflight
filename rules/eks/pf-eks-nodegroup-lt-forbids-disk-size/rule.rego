package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-lt-forbids-disk-size", "ERROR", name,
	"Properties.DiskSize",
	"DiskSize is set alongside LaunchTemplate; the disk has to come from the launch template (\"Disk size must be specified within the launch template.\")",
	"Drop DiskSize and size the volume in the launch template's BlockDeviceMappings",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	_pf_ekslib_has(name, "LaunchTemplate")
	_pf_ekslib_has(name, "DiskSize")
}
