package cdk_preflight

import rego.v1

_pf_sqsrap_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqsrap_fix := "Use byQueue with 1-10 sourceQueueArns, or allowAll / denyAll without sourceQueueArns"

# RedriveAllowPolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_sqsrap_pol(name) := pol if {
	pol := object.get(input.resources[name].properties, "RedriveAllowPolicy", null)
	is_object(pol)
}

_pf_sqsrap_pol(name) := pol if {
	raw := object.get(input.resources[name].properties, "RedriveAllowPolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

_pf_sqsrap_msg := "Amazon SQS can't create the redrive allow policy"

violation contains make_diag_full("pf-sqs-redrive-allow-policy", "ERROR", name,
	"Properties.RedriveAllowPolicy.redrivePermission",
	sprintf("RedriveAllowPolicy has no redrivePermission; CreateQueue fails with \"%s, as it's in an unsupported format.\"", [_pf_sqsrap_msg]),
	_pf_sqsrap_fix, _pf_sqsrap_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrap_pol(name)
	object.get(pol, "redrivePermission", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-sqs-redrive-allow-policy", "ERROR", name,
	"Properties.RedriveAllowPolicy.redrivePermission",
	sprintf("redrivePermission '%s' is not allowAll, denyAll or byQueue; CreateQueue fails with \"%s, as it's in an unsupported format.\"", [perm, _pf_sqsrap_msg]),
	_pf_sqsrap_fix, _pf_sqsrap_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	perm := object.get(_pf_sqsrap_pol(name), "redrivePermission", null)
	is_string(perm)
	not perm in {"allowAll", "denyAll", "byQueue"}
}

violation contains make_diag_full("pf-sqs-redrive-allow-policy", "ERROR", name,
	"Properties.RedriveAllowPolicy.sourceQueueArns",
	sprintf("redrivePermission byQueue has %d sourceQueueArns (1 to 10 required); CreateQueue fails with \"%s. When you specify the byQueue permission type, you must also specify between 1 and 10 source queue ARNs.\"", [n, _pf_sqsrap_msg]),
	_pf_sqsrap_fix, _pf_sqsrap_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrap_pol(name)
	object.get(pol, "redrivePermission", null) == "byQueue"
	n := _pf_sqsrap_count(object.get(pol, "sourceQueueArns", null))
	_pf_sqsrap_out(n)
}

_pf_sqsrap_count(v) := 0 if v == null

_pf_sqsrap_count(v) := count(v) if is_array(v)

_pf_sqsrap_out(n) if n < 1

_pf_sqsrap_out(n) if n > 10

violation contains make_diag_full("pf-sqs-redrive-allow-policy", "ERROR", name,
	"Properties.RedriveAllowPolicy.sourceQueueArns",
	sprintf("redrivePermission %s does not take sourceQueueArns; CreateQueue fails with \"%s. You can specify source queue ARNs only when the permission type is byQueue.\"", [perm, _pf_sqsrap_msg]),
	_pf_sqsrap_fix, _pf_sqsrap_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrap_pol(name)
	perm := object.get(pol, "redrivePermission", null)
	perm in {"allowAll", "denyAll"}
	object.get(pol, "sourceQueueArns", "__pf_absent") != "__pf_absent"
}
