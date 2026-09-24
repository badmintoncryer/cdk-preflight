package cdk_preflight

import rego.v1

# After は「既にあるルールの名前」で、SES は無い名前を拒否する。テンプレートが
# ルールセットごと作っているなら、そこに在るルールはテンプレートが作るものだけなので、
# 名前の集合を突き合わせられるのはこのパックだけ。
_pf_sesaft_rules := resources_of_type("AWS::SES::ReceiptRule")

_pf_sesaft_name(r) := n if {
	n := resolve(r, "Properties.Rule.Name")
	_pf_ses_lit(n)
}

_pf_sesaft_names := {n | some r in _pf_sesaft_rules; n := _pf_sesaft_name(r)}

# 名前をリテラルで書いていないルールが 1 本でもあると「その名前は無い」と言えない。
# 集合が不完全なときは降りる。
_pf_sesaft_complete if count(_pf_sesaft_names) == count(_pf_sesaft_rules)

violation contains make_diag_full("pf-ses-receipt-rule-after-exists", "ERROR", name,
	"Properties.After",
	sprintf("After names '%v', which no receipt rule in this template creates; the stack fails with \"Rule does not exist: %v\"", [after, after]),
	"Point After at another AWS::SES::ReceiptRule in the template with Ref, or drop it to insert the rule at the head of the rule set",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_ReceiptRule.html") if {
	some name in _pf_sesaft_rules
	after := resolve(name, "Properties.After")
	_pf_ses_lit(after)
	after != ""
	# ルールセットもテンプレートが作っている＝作成時は空で、ほかにルールは居ない。
	# 既存のルールセットを指している場合は、コンソールで足したルール（ドリフト）が
	# 在りえるので判定しない。
	resolve(name, "Properties.RuleSetName") in resources_of_type("AWS::SES::ReceiptRuleSet")
	_pf_sesaft_complete
	not after in _pf_sesaft_names
}
