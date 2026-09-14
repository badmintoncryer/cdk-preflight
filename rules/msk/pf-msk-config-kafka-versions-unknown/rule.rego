package cdk_preflight

import rego.v1

# CreateConfiguration rejects a version string it does not know with "Unsupported KafkaVersion [x].
# Valid values: [...]". Deprecated versions are still valid values here, so the list below is every
# version `aws kafka list-kafka-versions` reports, ACTIVE and DEPRECATED alike (2026-09-13), which
# is exactly the list the service prints.
# ponytail: a static list goes stale the day AWS ships a new version -- refresh it from
# list-kafka-versions when the monthly bench or a user reports a false positive.
_pf_mskkvu_known := {
	"1.1.1",
	"2.1.0",
	"2.2.1",
	"2.3.1",
	"2.4.1",
	"2.4.1.1",
	"2.5.1",
	"2.6.0",
	"2.6.1",
	"2.6.2",
	"2.6.3",
	"2.7.0",
	"2.7.1",
	"2.7.2",
	"2.8.0",
	"2.8.1",
	"2.8.2.tiered",
	"3.1.1",
	"3.2.0",
	"3.3.1",
	"3.3.2",
	"3.4.0",
	"3.5.1",
	"3.6.0",
	"3.6.0.1",
	"3.7.x",
	"3.7.x.kraft",
	"3.8.x",
	"3.8.x.kraft",
	"3.8.link",
	"3.9.x",
	"3.9.x.kraft",
	"4.0.x.kraft",
	"4.1.x.kraft",
	"4.2.x.kraft",
}

violation contains make_diag_full("pf-msk-config-kafka-versions-unknown", "ERROR", name,
	"Properties.KafkaVersionsList",
	sprintf("KafkaVersionsList contains '%s', which is not an Amazon MSK Kafka version; the create fails with \"Unsupported KafkaVersion [%s]\"", [v, v]),
	"Use a version reported by `aws kafka list-kafka-versions` (for example 3.9.x or 3.9.x.kraft)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-configuration.html") if {
	some name in resources_of_type("AWS::MSK::Configuration")
	some it in flatten_list(name, "Properties.KafkaVersionsList")
	v := it.value
	is_string(v)
	not v in _pf_mskkvu_known
}
