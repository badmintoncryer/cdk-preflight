package cdk_preflight

import rego.v1

# RuleSetName は ASCII 英数と `_` `-` だけで、先頭と末尾は英数。レジストリスキーマは
# pattern を一切持たないので、`-` で始まる名前は合成も cfn-lint も通り抜ける。
violation contains make_diag_full("pf-ses-receipt-rule-set-name-charset", "ERROR", name,
	"Properties.RuleSetName",
	sprintf("RuleSetName '%v' is not a valid rule set name; the stack fails with \"Not a valid ruleSetName: %v\"", [n, n]),
	"Use only ASCII letters, digits, underscores and dashes, and start and end with a letter or digit",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_CreateReceiptRuleSet.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRuleSet")
	n := resolve(name, "Properties.RuleSetName")
	_pf_ses_lit(n)
	n != ""
	not regex.match(`^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$`, n)
}
