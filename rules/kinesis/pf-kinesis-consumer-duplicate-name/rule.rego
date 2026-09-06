package cdk_preflight

import rego.v1

# E3019 only guards a type's primary identifier, and a consumer's is its
# ConsumerARN — the (stream, name) pair it is really keyed by is not checked.
violation contains make_diag_full("pf-kinesis-consumer-duplicate-name", "ERROR", b,
	"Properties.ConsumerName",
	sprintf("consumer name '%v' is already registered on the same stream by resource %v; the stack fails with \"Consumer %v under stream ... already exists\"", [cn, a, cn]),
	"Give each consumer of a stream a distinct ConsumerName",
	"https://docs.aws.amazon.com/kinesis/latest/APIReference/API_RegisterStreamConsumer.html") if {
	some a in resources_of_type("AWS::Kinesis::StreamConsumer")
	some b in resources_of_type("AWS::Kinesis::StreamConsumer")
	a < b
	cn := resolve(a, "Properties.ConsumerName")
	is_string(cn)
	resolve(b, "Properties.ConsumerName") == cn
	sa := resolve(a, "Properties.StreamARN")
	is_string(sa)
	resolve(b, "Properties.StreamARN") == sa
}
