package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-lt-id-or-name-required", "ERROR", name,
	"Properties.LaunchTemplate",
	"LaunchTemplate names neither Id nor Name (\"Either a launch template ID or a launch template name must be specified in the request.\")",
	"Add the launch template's Id or Name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-launchtemplatespecification.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	lts := _pf_ekslib_get(name, "LaunchTemplate")
	is_object(lts)
	not _pf_ekslib_ohas(lts, "Id")
	not _pf_ekslib_ohas(lts, "Name")
}
