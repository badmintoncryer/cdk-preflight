package cdk_preflight

import rego.v1

# Category x Owner x Provider must be a published combination. Providers absent
# from _pf_cplib_aws_providers are never judged, so a newly published provider
# costs a miss rather than a false positive; Owner "Custom" is skipped entirely
# because its provider name is chosen by the user.
violation contains make_diag_full("pf-codepipeline-action-type-id-combination", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.ActionTypeId", [si, ai]),
	sprintf("action '%v' pairs Category '%v' with the AWS provider '%v', which is published under %v; CreatePipeline fails with \"ActionType (Category: '%v', Provider: '%v', Owner: 'AWS', Version: '1') in action '%v' is not available in region\"", [an, cat, prov, ok, cat, prov, an]),
	sprintf("Set Category to one of %v, or pick the provider that serves this category", [ok]),
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-valid-providers.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	tid := _pf_cplib_tid(a)
	object.get(tid, "Owner", "AWS") == "AWS"
	prov := object.get(tid, "Provider", "")
	cats := _pf_cplib_aws_providers[prov]
	cat := _pf_cplib_category(a)
	not cat in cats
	ok := concat(", ", sort(cats))
	an := object.get(a, "Name", "")
}

# The mirror case: an AWS provider name declared under Owner ThirdParty.
violation contains make_diag_full("pf-codepipeline-action-type-id-combination", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.ActionTypeId.Owner", [si, ai]),
	sprintf("action '%v' declares Owner 'ThirdParty' for '%v', which is an AWS-provided action provider; CreatePipeline fails with \"ActionType (Category: '%v', Provider: '%v', Owner: 'ThirdParty', Version: '1') in action '%v' is not available in region\"", [an, prov, cat, prov, an]),
	"Set Owner to AWS for an AWS-provided action provider",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-valid-providers.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	tid := _pf_cplib_tid(a)
	object.get(tid, "Owner", "AWS") == "ThirdParty"
	prov := object.get(tid, "Provider", "")
	_pf_cplib_aws_providers[prov]
	cat := _pf_cplib_category(a)
	an := object.get(a, "Name", "")
}
