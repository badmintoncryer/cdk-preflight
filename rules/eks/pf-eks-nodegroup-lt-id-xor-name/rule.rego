package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-lt-id-xor-name", "ERROR", name,
	"Properties.LaunchTemplate",
	"LaunchTemplate sets both Id and Name (\"Either provide launch template ID or launch template name in the request.\")",
	"Identify the launch template by Id or by Name, not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-launchtemplatespecification.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	lts := _pf_ekslib_get(name, "LaunchTemplate")
	_pf_ekslib_ohas(lts, "Id")
	_pf_ekslib_ohas(lts, "Name")
}
