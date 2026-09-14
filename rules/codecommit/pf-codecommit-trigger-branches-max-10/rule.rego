package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-branches-max-10", "ERROR", name,
	sprintf("Properties.Triggers.%d.Branches", [i]),
	sprintf("The trigger lists %d branches; the handler's PutRepositoryTriggers fails with \"A repository trigger cannot have more than 10 branches.\"", [count(br)]),
	"List at most 10 branches on a trigger, or list none to watch every branch",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_RepositoryTrigger.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	br := object.get(t, "Branches", [])
	is_array(br)
	count(br) > 10
}
