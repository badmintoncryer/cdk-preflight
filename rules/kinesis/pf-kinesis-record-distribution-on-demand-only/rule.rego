package cdk_preflight

import rego.v1

# StreamModeDetails defaults to PROVISIONED when omitted.
violation contains make_diag_full("pf-kinesis-record-distribution-on-demand-only", "ERROR", name,
	"Properties.RecordDistributionStrategy",
	sprintf("RecordDistributionStrategy is set on a %v stream; the stream create fails with \"RecordDistributionStrategy can only be set for ON_DEMAND streams\"", [mode]),
	"Use StreamMode ON_DEMAND, or drop RecordDistributionStrategy",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesis-stream.html") if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	resolve(name, "Properties.RecordDistributionStrategy") != null
	mode := _pf_kinrd_mode(name)
	is_string(mode)
	_pf_is_lit(mode)
	mode != "ON_DEMAND"
}

_pf_kinrd_mode(name) := m if {
	m := resolve(name, "Properties.StreamModeDetails.StreamMode")
	m != null
} else := "PROVISIONED"
