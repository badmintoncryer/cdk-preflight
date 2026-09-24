package cdk_preflight

import rego.v1

# One rule, not three: the service checks format, lower bound and upper bound
# with the same pair of schema regexes and answers with the same message for
# all of them. The two patterns are quoted verbatim from that message
# (2026-09-25, us-east-1) - together they mean 1d-3650d and 24h-87600h.

_pf_aoss_ret_d := `^(?:[1-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-2][0-9]{3}|[3][0-5][0-9]{2}|[3][6][0-4][0-9]|3650)d$`

_pf_aoss_ret_h := `^(?:8[0-6][0-9]{3}|87[0-5][0-9]{2}|87600|[1-7][0-9]{3}|[1-9][0-9]{2}|[3-9][0-9]|[2][4-9])h$`

violation contains make_diag_full("pf-aoss-lifecycle-retention", "ERROR", name,
	sprintf("%v.MinIndexRetention", [p]),
	sprintf("MinIndexRetention %v is outside 24h-87600h / 1d-3650d; CreateLifecyclePolicy answers \"Policy json is invalid, error: [$.Rules[0].MinIndexRetention: does not match the regex pattern ...]\"", [v]),
	"Write the retention as <n>d (1-3650) or <n>h (24-87600), or use NoMinIndexRetention",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html") if {
	some name in _pf_aoss_life
	some [p, r] in _pf_aoss_rules_at(name)
	v := object.get(r, "MinIndexRetention", null)
	is_string(v)
	not regex.match(_pf_aoss_ret_d, v)
	not regex.match(_pf_aoss_ret_h, v)
}
