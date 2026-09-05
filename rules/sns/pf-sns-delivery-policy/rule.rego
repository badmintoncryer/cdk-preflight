package cdk_preflight

import rego.v1

_pf_snsdp_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-message-delivery-retries.html"

_pf_snsdp_fix := "Keep the retry policy inside the documented ranges (see the delivery policy table)"

# [name, path prefix, healthyRetryPolicy object, throttlePolicy object or null]
_pf_snsdp_obj(v) := v if is_object(v)

_pf_snsdp_obj(v) := o if {
	is_string(v)
	o := json.unmarshal(v)
	is_object(o)
}

_pf_snsdp_pol contains [name, "Properties.DeliveryPolicy", dp] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	dp := _pf_snsdp_obj(object.get(input.resources[name].properties, "DeliveryPolicy", null))
}

_pf_snsdp_pol contains [name, "Properties.DeliveryPolicy.http", dp] if {
	some name in resources_of_type("AWS::SNS::Topic")
	top := _pf_snsdp_obj(object.get(input.resources[name].properties, "DeliveryPolicy", null))
	dp := object.get(top, "http", null)
	is_object(dp)
}

_pf_snsdp_retry contains [name, path, hr] if {
	some [name, p, dp] in _pf_snsdp_pol
	some key in ["healthyRetryPolicy", "defaultHealthyRetryPolicy"]
	hr := object.get(dp, key, null)
	is_object(hr)
	path := sprintf("%s.%s", [p, key])
}

_pf_snsdp_min contains ["minDelayTarget", 1]

_pf_snsdp_min contains ["numRetries", 0]

_pf_snsdp_min contains ["numNoDelayRetries", 0]

_pf_snsdp_min contains ["numMinDelayRetries", 0]

_pf_snsdp_min contains ["numMaxDelayRetries", 0]

_pf_snsdp_max contains ["maxDelayTarget", 3600]

_pf_snsdp_max contains ["numRetries", 100]

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.%s", [path, f]),
	sprintf("%s %v is below %v; the create call fails with \"DeliveryPolicy: ...%s must be greater than or equal to %v\"", [f, v, m, f, m]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, path, hr] in _pf_snsdp_retry
	some [f, m] in _pf_snsdp_min
	v := object.get(hr, f, null)
	is_number(v)
	v < m
}

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.%s", [path, f]),
	sprintf("%s %v is above %v; the create call fails with \"DeliveryPolicy: ...%s must be less than or equal to %v\"", [f, v, m, f, m]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, path, hr] in _pf_snsdp_retry
	some [f, m] in _pf_snsdp_max
	v := object.get(hr, f, null)
	is_number(v)
	v > m
}

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.maxDelayTarget", [path]),
	sprintf("maxDelayTarget %v is below minDelayTarget %v; the create call fails with \"DeliveryPolicy: ...maxDelayTarget must be greater than or equal to minDelayTarget\"", [mx, mn]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, path, hr] in _pf_snsdp_retry
	mn := object.get(hr, "minDelayTarget", null)
	mx := object.get(hr, "maxDelayTarget", null)
	is_number(mn)
	is_number(mx)
	mx < mn
}

_pf_snsdp_phase(hr, f) := v if {
	v := object.get(hr, f, null)
	is_number(v)
}

_pf_snsdp_phase(hr, f) := 0 if not is_number(object.get(hr, f, null))

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.numRetries", [path]),
	sprintf("numRetries %v is below the phase total %v (numNoDelayRetries + numMinDelayRetries + numMaxDelayRetries); the create call fails with \"DeliveryPolicy: ...numRetries must be greater than or equal to total of numMinDelayRetries, numNoDelayRetries and numMaxDelayRetries\"", [n, total]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, path, hr] in _pf_snsdp_retry
	n := object.get(hr, "numRetries", null)
	is_number(n)
	total := (_pf_snsdp_phase(hr, "numNoDelayRetries") + _pf_snsdp_phase(hr, "numMinDelayRetries")) + _pf_snsdp_phase(hr, "numMaxDelayRetries")
	n < total
}

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.backoffFunction", [path]),
	sprintf("backoffFunction '%s' is not arithmetic, exponential, geometric or linear; the create call fails with \"DeliveryPolicy: ... the value [%s] is not a valid backoff function\"", [b, b]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, path, hr] in _pf_snsdp_retry
	b := object.get(hr, "backoffFunction", null)
	is_string(b)
	not b in {"arithmetic", "exponential", "geometric", "linear"}
}

violation contains make_diag_full("pf-sns-delivery-policy", "ERROR", name,
	sprintf("%s.%s.maxReceivesPerSecond", [p, key]),
	sprintf("maxReceivesPerSecond %v is below 1; the create call fails with \"DeliveryPolicy: throttlePolicy.maxReceivesPerSecond must be >= 1\"", [v]),
	_pf_snsdp_fix, _pf_snsdp_url) if {
	some [name, p, dp] in _pf_snsdp_pol
	some key in ["throttlePolicy", "defaultThrottlePolicy"]
	tp := object.get(dp, key, null)
	is_object(tp)
	v := object.get(tp, "maxReceivesPerSecond", null)
	is_number(v)
	v < 1
}
