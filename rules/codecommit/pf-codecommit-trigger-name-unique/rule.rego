package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-name-unique", "ERROR", name,
	sprintf("Properties.Triggers.%d.Name", [j]),
	sprintf("Two triggers are both named %v; the handler's PutRepositoryTriggers fails with \"Duplicate repository trigger names are not allowed\"", [n]),
	"Give every trigger on the repository its own name",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutRepositoryTriggers.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	ts := _pf_cclib_triggers(name)
	some i, t in ts
	some j, u in ts
	i < j
	is_object(t)
	is_object(u)
	n := object.get(t, "Name", "")
	_pf_cclib_lit(n)
	n != ""
	n == object.get(u, "Name", "")
}
