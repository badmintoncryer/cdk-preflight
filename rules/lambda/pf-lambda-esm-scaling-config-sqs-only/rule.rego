package cdk_preflight

import rego.v1

_pf_lescs_fix := "Drop ScalingConfig, or point the mapping at an SQS queue"

_pf_lescs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-scalingconfig.html"

violation contains make_diag_full("pf-lambda-esm-scaling-config-sqs-only", "ERROR", name,
	"Properties.ScalingConfig",
	"ScalingConfig on a non-SQS event source; MaximumConcurrency is an SQS-only control and the mapping create is rejected",
	_pf_lescs_fix, _pf_lescs_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "ScalingConfig")
	_pf_lam_not(name, "sqs")
}
