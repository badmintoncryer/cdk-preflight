package cdk_preflight

import rego.v1

_pf_lekpg_fix := "Drop PollerGroupName; poller groups are a Kafka-only feature"

_pf_lekpg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-provisionedpollerconfig.html"

violation contains make_diag_full("pf-lambda-esm-poller-group-name-kafka-only", "ERROR", name,
	"Properties.ProvisionedPollerConfig.PollerGroupName",
	"PollerGroupName on a non-Kafka event source; poller groups share pollers across Kafka mappings only",
	_pf_lekpg_fix, _pf_lekpg_url) if {
	some name in _pf_lam_esm
	object.get(_pf_lam_ppc(name), "PollerGroupName", "") != ""
	_pf_lam_arn_not(name, "kafka")
}
