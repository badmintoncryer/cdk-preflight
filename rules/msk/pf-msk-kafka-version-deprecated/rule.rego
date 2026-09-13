package cdk_preflight

import rego.v1

# MSK keeps deprecated versions readable in list-kafka-versions but refuses to create with them:
# "Standard instance types are not supported for Kafka version 2.8.1. Valid values: [...] ...
# InvalidParameter: kafkaVersion". The set below is every version whose only status was
# DEPRECATED on 2026-09-14 (aws kafka list-kafka-versions, us-east-1); 3.9.x and 4.2.x.kraft are
# listed twice by the API and stay out because their other row is ACTIVE.
violation contains make_diag_full("pf-msk-kafka-version-deprecated", "ERROR", name,
	"Properties.KafkaVersion",
	sprintf("Apache Kafka %s is deprecated; the create fails with \"Standard instance types are not supported for Kafka version %s\"", [v, v]),
	"Pick a version that aws kafka list-kafka-versions still reports as ACTIVE",
	"https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	v := resolve(name, "Properties.KafkaVersion")
	v in _pf_mskkvd_deprecated
}

_pf_mskkvd_deprecated := {
	"1.1.1", "2.1.0", "2.2.1", "2.3.1", "2.4.1", "2.4.1.1",
	"2.5.1", "2.6.0", "2.6.1", "2.6.2", "2.6.3",
	"2.7.0", "2.7.1", "2.7.2", "2.8.0", "2.8.1", "2.8.2.tiered",
	"3.1.1", "3.2.0", "3.3.1", "3.3.2", "3.4.0", "3.5.1",
	"3.6.0.1", "3.8.link",
}
