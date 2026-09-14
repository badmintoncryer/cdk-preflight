package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-custom-data-max-1000", "ERROR", name,
	sprintf("Properties.Triggers.%d.CustomData", [i]),
	sprintf("Trigger CustomData is %d characters; the handler's PutRepositoryTriggers fails with \"Repository trigger custom data cannot exceed 1000 characters\"", [count(cd)]),
	"Shorten CustomData to 1000 characters or fewer",
	"https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	cd := object.get(t, "CustomData", "")
	_pf_cclib_lit(cd)
	count(cd) > 1000
}
