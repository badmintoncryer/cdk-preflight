package cdk_preflight

import rego.v1

_pf_snsfo_url := "https://docs.aws.amazon.com/sns/latest/api/API_CreateTopic.html"

_pf_snsfo_fix := "Set FifoTopic: true (with a *.fifo TopicName) or drop the FIFO-only attributes; keep the archive retention within 1-365 days"

_pf_snsfo_std(t) if {
	props := input.resources[t].properties
	is_object(props)
	object.get(props, "FifoTopic", "__pf_absent") == "__pf_absent"
}

_pf_snsfo_std(t) if resolve(t, "Properties.FifoTopic") in {false, "false"}

violation contains make_diag_full("pf-sns-fifo-only-attributes", "ERROR", name,
	sprintf("Properties.%s", [attr]),
	sprintf("%s is set on a standard topic (FifoTopic is not true); CreateTopic fails with \"Invalid parameter: Attributes Reason: Unknown attribute %s\"", [attr, attr]),
	_pf_snsfo_fix, _pf_snsfo_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	_pf_snsfo_std(name)
	some attr in ["ContentBasedDeduplication", "ArchivePolicy", "FifoThroughputScope"]
	props := input.resources[name].properties
	is_object(props)
	object.get(props, attr, "__pf_absent") != "__pf_absent"
}

_pf_snsfo_archive(name) := pol if {
	pol := object.get(input.resources[name].properties, "ArchivePolicy", null)
	is_object(pol)
}

_pf_snsfo_archive(name) := pol if {
	raw := object.get(input.resources[name].properties, "ArchivePolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

_pf_snsfo_num(v) := v if is_number(v)

_pf_snsfo_num(v) := to_number(v) if {
	is_string(v)
	regex.match("^[0-9]+$", v)
}

violation contains make_diag_full("pf-sns-fifo-only-attributes", "ERROR", name,
	"Properties.ArchivePolicy.MessageRetentionPeriod",
	sprintf("ArchivePolicy.MessageRetentionPeriod %v is outside 1..365 days; CreateTopic fails with \"Invalid parameter: Attributes Reason: ArchivePolicy: MessageRetentionPeriod value is invalid\"", [n]),
	_pf_snsfo_fix, _pf_snsfo_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	n := _pf_snsfo_num(object.get(_pf_snsfo_archive(name), "MessageRetentionPeriod", null))
	_pf_snsfo_out(n)
}

_pf_snsfo_out(n) if n < 1

_pf_snsfo_out(n) if n > 365
