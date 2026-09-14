package cdk_preflight

import rego.v1

# Every Includes/Excludes list under a push or pull-request filter caps at 8.
violation contains make_diag_full("pf-codepipeline-trigger-filter-patterns-max-8", "ERROR", name,
	sprintf("Properties.Triggers.%v.GitConfiguration.%v.%v.%v.%v", [ti, kind, fi, scope, side]),
	sprintf("the %v list holds %d patterns; CreatePipeline fails with \"failed to satisfy constraint: Member must have length less than or equal to 8\"", [side, n]),
	"Keep each Includes/Excludes list to 8 patterns or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_GitConfiguration.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some ti, t in object.get(_pf_cplib_props(name), "Triggers", [])
	g := _pf_cplib_get(t, "GitConfiguration")
	_pf_cplib_plain(g)
	some kind in ["Push", "PullRequest"]
	some fi, f in object.get(g, kind, [])
	_pf_cplib_plain(f)
	some scope in ["Branches", "FilePaths", "Tags"]
	s := object.get(f, scope, {})
	_pf_cplib_plain(s)
	some side in ["Includes", "Excludes"]
	n := count(object.get(s, side, []))
	n > 8
}
