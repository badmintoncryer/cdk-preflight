package cdk_preflight

import rego.v1

_pf_leklc_fix := "Drop LoggingConfig, or point the mapping at an MSK cluster or self-managed Kafka"

_pf_leklc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-logging-config-kafka-only", "ERROR", name,
	"Properties.LoggingConfig",
	"LoggingConfig on a non-Kafka event source; poller logging exists only for Kafka event sources",
	_pf_leklc_fix, _pf_leklc_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "LoggingConfig")
	_pf_lam_arn_not(name, "kafka")
}
