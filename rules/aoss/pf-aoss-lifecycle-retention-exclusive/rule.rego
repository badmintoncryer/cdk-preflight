package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-lifecycle-retention-exclusive", "ERROR", name,
	sprintf("%v.NoMinIndexRetention", [p]),
	"the rule sets both MinIndexRetention and NoMinIndexRetention; CreateLifecyclePolicy answers \"Policy json is invalid, error: [$.Rules[0]: should be valid to one and only one of schema, but more than one are valid]\"",
	"Keep one of the two: MinIndexRetention for a minimum age, NoMinIndexRetention to keep indexes forever",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html") if {
	some name in _pf_aoss_life
	some [p, r] in _pf_aoss_rules_at(name)
	object.get(r, "MinIndexRetention", "__pf_absent") != "__pf_absent"
	object.get(r, "NoMinIndexRetention", "__pf_absent") != "__pf_absent"
}
