package cdk_preflight

import rego.v1

_pf_lepps_fix := "Drop ProvisionedPollerConfig, or point the mapping at an SQS queue or a Kafka cluster"

_pf_lepps_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-provisioned-poller-source-support", "ERROR", name,
	"Properties.ProvisionedPollerConfig",
	"ProvisionedPollerConfig on a source that does not support it; provisioned mode exists only for SQS and Kafka event sources",
	_pf_lepps_fix, _pf_lepps_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "ProvisionedPollerConfig")
	some other in ["kinesis","dynamodb","mq","docdb"]
	_pf_lam_is(name, other)
}
