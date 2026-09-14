package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-triggers-max-10", "ERROR", name,
	"Properties.Triggers",
	sprintf("The repository declares %d triggers; the handler's PutRepositoryTriggers fails with \"Trigger limit for a particular repository is 10\"", [count(ts)]),
	"Declare at most 10 triggers on a repository",
	"https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	ts := _pf_cclib_triggers(name)
	count(ts) > 10
}
