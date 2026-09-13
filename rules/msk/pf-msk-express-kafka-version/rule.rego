package cdk_preflight

import rego.v1

# Express brokers support a subset of the ACTIVE Apache Kafka versions (3.6, 3.8, 3.9 and 4.2 as
# of 2026-09-14) - 3.7.x is perfectly valid for Standard brokers and rejected here with "Express
# instance types are not supported for Kafka version 3.7.x". This is a deny list on purpose: an
# allow list would turn every version AWS adds into a false positive.
violation contains make_diag_full("pf-msk-express-kafka-version", "ERROR", name,
	"Properties.KafkaVersion",
	sprintf("Express instance type '%s' with Apache Kafka %s; the create fails with \"Express instance types are not supported for Kafka version %s\"", [itype, v, v]),
	"Run Express brokers on an Apache Kafka version they support (3.6, 3.8, 3.9 or 4.2)",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-broker-types-express.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	itype := resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType")
	is_string(itype)
	startswith(itype, "express.")
	v := resolve(name, "Properties.KafkaVersion")
	v in _pf_mskekv_not_on_express
}

# ACTIVE versions (aws kafka list-kafka-versions) that Express brokers do not run.
_pf_mskekv_not_on_express := {"3.7.x", "3.7.x.kraft", "4.0.x.kraft", "4.1.x.kraft"}
