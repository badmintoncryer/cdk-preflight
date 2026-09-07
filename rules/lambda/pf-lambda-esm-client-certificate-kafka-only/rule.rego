package cdk_preflight

import rego.v1

_pf_lekcc_fix := "Use BASIC_AUTH for Amazon MQ; mTLS is a Kafka credential type"

_pf_lekcc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-sourceaccessconfiguration.html"

violation contains make_diag_full("pf-lambda-esm-client-certificate-kafka-only", "ERROR", name,
	sprintf("Properties.SourceAccessConfigurations[%v].Type", [i]),
	"CLIENT_CERTIFICATE_TLS_AUTH on an Amazon MQ event source; that credential type is only accepted for MSK and self-managed Kafka",
	_pf_lekcc_fix, _pf_lekcc_url) if {
	some name in _pf_lam_esm
	some i, c in _pf_lam_list(_pf_lam_get(name, "SourceAccessConfigurations"))
	is_object(c)
	object.get(c, "Type", "") == "CLIENT_CERTIFICATE_TLS_AUTH"
	_pf_lam_arn_not(name, "kafka")
}
