package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-update-config-xor", "ERROR", name,
	"Properties.UpdateConfig",
	"UpdateConfig sets both MaxUnavailable and MaxUnavailablePercentage (\"Either provide max-unavailable or max-unavailable-percentage in the request.\")",
	"Keep one of MaxUnavailable or MaxUnavailablePercentage",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-updateconfig.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	uc := _pf_ekslib_get(name, "UpdateConfig")
	_pf_ekslib_ohas(uc, "MaxUnavailable")
	_pf_ekslib_ohas(uc, "MaxUnavailablePercentage")
}
