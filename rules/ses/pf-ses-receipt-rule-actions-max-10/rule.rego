package cdk_preflight

import rego.v1

# 「受信ルールあたりのアクション数 10」は調整不可のクォータ（quotas ページの
# Adjustable = No）。スキーマは Actions に maxItems を持たない。
violation contains make_diag_full("pf-ses-receipt-rule-actions-max-10", "ERROR", name,
	"Properties.Rule.Actions",
	sprintf("Rule.Actions has %d actions; SES allows 10 per receipt rule and the stack fails with \"Too many actions\"", [n]),
	"Keep at most 10 actions in one receipt rule and move the rest to another rule",
	"https://docs.aws.amazon.com/ses/latest/dg/quotas.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRule")
	n := count([e | some e in _pf_sesrx_actions(name); not _pf_sesrx_marker(e)])
	n > 10
}
