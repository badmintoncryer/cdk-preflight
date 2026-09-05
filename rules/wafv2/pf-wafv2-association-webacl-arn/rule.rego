package cdk_preflight

import rego.v1

_pf_wafawa_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociateWebACL.html"

_pf_wafawa_fix := "Pass Fn::GetAtt WebACL.Arn of a REGIONAL web ACL in this stack, or a regional/webacl ARN from the same region"

_pf_wafawa_msg := "AssociateWebACL fails with \"The ARN isn't valid. A valid ARN begins with arn: and includes other information separated by colons or slashes.\""

_pf_wafawa_lit(name) := _pf_waflib_lit(name, "Properties.WebACLArn")

violation contains make_diag_full("pf-wafv2-association-webacl-arn", "ERROR", name, "Properties.WebACLArn",
	sprintf("'%s' is not the ARN of a WAFv2 web ACL; %s", [s, _pf_wafawa_msg]),
	_pf_wafawa_fix, _pf_wafawa_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafawa_lit(name)
	not regex.match("^arn:[^:]+:wafv2:[^:]+:[^:]*:(global|regional)/webacl/", s)
}

# Needs the deploy environment (enforce mode only).
violation contains make_diag_full("pf-wafv2-association-webacl-arn", "ERROR", name, "Properties.WebACLArn",
	sprintf("web ACL ARN is in region '%s' but the association deploys to '%s' (a CLOUDFRONT-scoped web ACL lives in us-east-1 and cannot be associated through WebACLAssociation elsewhere); %s", [parts[3], region, _pf_wafawa_msg]),
	_pf_wafawa_fix, _pf_wafawa_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafawa_lit(name)
	regex.match("^arn:[^:]+:wafv2:[^:]+:[^:]*:(global|regional)/webacl/", s)
	parts := _pf_waflib_arn(s)
	parts[3] != region
}

violation contains make_diag_full("pf-wafv2-association-webacl-arn", "ERROR", name, "Properties.WebACLArn",
	sprintf("references %s, which is not an AWS::WAFv2::WebACL; %s", [x, _pf_wafawa_msg]),
	_pf_wafawa_fix, _pf_wafawa_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	x := _pf_waflib_getatt(input.resources[name].properties.WebACLArn)
	input.resources[x]
	not x in resources_of_type("AWS::WAFv2::WebACL")
}
