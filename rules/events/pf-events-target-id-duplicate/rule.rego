package cdk_preflight

import rego.v1

# Target ids are the update key for a rule's targets, so PutTargets refuses a
# repeat: "Parameter targets is not valid. Reason: More than one target with
# Id '<id>' is provided." Measured 2026-09-07, us-east-1.
_pf_evtid_ids(name) := [id |
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	id := object.get(t.value, "Id", null)
	is_string(id)
]

violation contains make_diag_full("pf-events-target-id-duplicate", "ERROR", name,
	"Properties.Targets",
	sprintf("Two targets share the Id '%s'; PutTargets fails with \"More than one target with Id '%s' is provided\"", [id, id]),
	"Give every target on the rule a distinct Id",
	"https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	ids := _pf_evtid_ids(name)
	some id in ids
	count([x | some x in ids; x == id]) > 1
}
