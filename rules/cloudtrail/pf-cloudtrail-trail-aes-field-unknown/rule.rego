package cdk_preflight

import rego.v1

# severity は WARN。サービス側の検査は eventCategory ごと（実機の文面は
# "The following field is not allowed when the eventCategory field value equals Management: ..."）だが、
# ここの allowlist は全カテゴリの和集合なので、カテゴリ外のフィールドは見逃す。逆に AWS が新しい
# フィールドを足すと誤検出になるため、ERROR で止めずに警告に留める。

_pf_ctfld_known := {
	"eventCategory", "eventName", "eventSource", "eventType", "errorCode",
	"readOnly", "resources.type", "resources.ARN",
	"sessionCredentialFromConsole", "userIdentity.arn", "vpcEndpointId",
}

violation contains make_diag_full("pf-cloudtrail-trail-aes-field-unknown", "WARN", name,
	"Properties.AdvancedEventSelectors.FieldSelectors.Field",
	sprintf("'%v' is not a CloudTrail event record field; PutEventSelectors rejects the selector", [fld]),
	"Use one of the documented fields (eventCategory, eventName, eventSource, eventType, errorCode, readOnly, resources.type, resources.ARN, sessionCredentialFromConsole, userIdentity.arn, vpcEndpointId)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some s in _pf_ctlib_aes(name)
	some fs in _pf_ctlib_field_selectors(s)
	fld := object.get(fs, "Field", null)
	is_string(fld)
	not fld in _pf_ctfld_known
}
