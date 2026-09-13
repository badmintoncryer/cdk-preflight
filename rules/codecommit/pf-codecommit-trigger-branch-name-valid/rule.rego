package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-branch-name-valid", "ERROR", name,
	sprintf("Properties.Triggers.%d.Branches.%d", [i, j]),
	sprintf("Branch %v is not a valid Git ref name; the handler's PutRepositoryTriggers fails with InvalidRepositoryTriggerBranchNameException", [b]),
	"Use a valid Git branch name: no spaces, no '..', '//' or '@{', none of ~^:?*[\\, no leading or trailing '/' or '.', and no '.lock' suffix",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_RepositoryTrigger.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	br := object.get(t, "Branches", [])
	is_array(br)
	some j, b in br
	_pf_cclib_bad_ref(b)
}
