package cdk_preflight

import rego.v1

# Both the Push and the PullRequest filter lists cap at 3 entries.
violation contains make_diag_full("pf-codepipeline-trigger-filters-max-3", "ERROR", name,
	sprintf("Properties.Triggers.%v.GitConfiguration.%v", [ti, kind]),
	sprintf("the %v filter list holds %d entries; CreatePipeline fails with \"failed to satisfy constraint: Member must have length less than or equal to 3\"", [kind, n]),
	"Keep the Push and PullRequest filter lists to 3 entries or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_GitConfiguration.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some ti, t in object.get(_pf_cplib_props(name), "Triggers", [])
	g := _pf_cplib_get(t, "GitConfiguration")
	_pf_cplib_plain(g)
	some kind in ["Push", "PullRequest"]
	_pf_countable_items(object.get(g, kind, []))
	n := count(object.get(g, kind, []))
	n > 3
}
