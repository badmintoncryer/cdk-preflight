package cdk_preflight

import rego.v1

_pf_leks5_fix := "Use BASIC_AUTH for Amazon MQ; SASL/SCRAM is a Kafka credential type"

_pf_leks5_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-sourceaccessconfiguration.html"

violation contains make_diag_full("pf-lambda-esm-sasl-scram-512-kafka-only", "ERROR", name,
	sprintf("Properties.SourceAccessConfigurations[%v].Type", [i]),
	"SASL_SCRAM_512_AUTH on an Amazon MQ event source; that credential type is only accepted for MSK and self-managed Kafka",
	_pf_leks5_fix, _pf_leks5_url) if {
	some name in _pf_lam_esm
	some i, c in _pf_lam_list(_pf_lam_get(name, "SourceAccessConfigurations"))
	is_object(c)
	object.get(c, "Type", "") == "SASL_SCRAM_512_AUTH"
	_pf_lam_arn_not(name, "kafka")
}
