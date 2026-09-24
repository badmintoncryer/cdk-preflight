package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-custom-ami-type-needs-lt", "ERROR", name,
	"Properties.AmiType",
	"AmiType is CUSTOM but no LaunchTemplate supplies the AMI (\"Launch template details can't be null for Custom ami type node group\")",
	"Add a LaunchTemplate whose ImageId is the custom AMI, or pick a managed AmiType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	resolve(name, "Properties.AmiType") == "CUSTOM"
	not _pf_ekslib_has(name, "LaunchTemplate")
}
