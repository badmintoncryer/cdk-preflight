package cdk_preflight

import rego.v1

# Actions の 1 要素は 8 種のアクションのうち 1 つしか表せない（doc: "An instance of this
# data type can represent only one action."）。スキーマは 8 つとも Required: No の
# optional プロパティとして並べているだけなので、2 つ書いても合成は通る。
# ゼロ個の側は見ない: 要素が intrinsic 由来だと「無い」と区別できず、正しいテンプレートで
# 鳴りうる（欠落を数で証明しない）。
violation contains make_diag_full("pf-ses-receipt-action-exactly-one", "ERROR", name,
	sprintf("Properties.Rule.Actions[%d]", [i]),
	sprintf("Actions[%d] carries %d actions (%v); the stack fails with \"Exactly one action type must be specified for each ReceiptAction\"", [i, count(named), concat(", ", sort(named))]),
	"Split the actions into one Actions entry each",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_ReceiptAction.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRule")
	some i, e in _pf_sesrx_actions(name)
	is_object(e)
	named := _pf_sesrx_named(e)
	count(named) > 1
}
