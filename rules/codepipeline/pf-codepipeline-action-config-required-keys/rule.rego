package cdk_preflight

import rego.v1

# Each AWS-owned action provider publishes a set of Configuration keys it
# requires; CreatePipeline rejects the pipeline when one is missing. The table
# lives in rules/_lib/codepipeline.rego and names only providers whose required
# set was confirmed against the service, so an unlisted provider is never judged.
violation contains make_diag_full("pf-codepipeline-action-config-required-keys", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.Configuration", [si, ai]),
	sprintf("the %v action '%v' has no Configuration.%v; CreatePipeline fails with \"Action configuration for action '%v' is missing required configuration '%v'\"", [key, an, req, an, req]),
	sprintf("Add %v to the action's Configuration", [req]),
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	tid := _pf_cplib_tid(a)
	object.get(tid, "Owner", "AWS") == "AWS"
	key := sprintf("%v/%v", [_pf_cplib_category(a), object.get(tid, "Provider", "")])
	some req in _pf_cplib_required_config[key]
	cfg := object.get(a, "Configuration", {})
	_pf_cplib_plain(cfg)
	_pf_cplib_absent(cfg, req)
	an := object.get(a, "Name", "")
}
