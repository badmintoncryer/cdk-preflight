package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-update-config-required", "ERROR", name,
	"Properties.UpdateConfig",
	"UpdateConfig is present but sets none of MaxUnavailable, MaxUnavailablePercentage or UpdateStrategy (\"UpdateConfig cannot be empty if set in the request.\")",
	"Drop UpdateConfig, or set one of MaxUnavailable, MaxUnavailablePercentage or UpdateStrategy",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-updateconfig.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	uc := _pf_ekslib_get(name, "UpdateConfig")
	is_object(uc)
	not _pf_ekslib_ohas(uc, "MaxUnavailable")
	not _pf_ekslib_ohas(uc, "MaxUnavailablePercentage")
	not _pf_ekslib_ohas(uc, "UpdateStrategy")
}
