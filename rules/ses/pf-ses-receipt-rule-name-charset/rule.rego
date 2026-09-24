package cdk_preflight

import rego.v1

# Rule.Name は ASCII 英数と `_` `-` `.` だけで、先頭と末尾は英数。ルールセット名とは
# 許す文字が違う（こちらは `.` を許す）ので、サービスのエラー文も別（ruleName / ruleSetName）。
violation contains make_diag_full("pf-ses-receipt-rule-name-charset", "ERROR", name,
	"Properties.Rule.Name",
	sprintf("Rule.Name '%v' is not a valid receipt rule name; the stack fails with \"Not a valid ruleName: %v\"", [n, n]),
	"Use only ASCII letters, digits, underscores, dashes and periods, and start and end with a letter or digit",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_ReceiptRule.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRule")
	n := resolve(name, "Properties.Rule.Name")
	_pf_ses_lit(n)
	n != ""
	not regex.match(`^[a-zA-Z0-9]([a-zA-Z0-9_.-]*[a-zA-Z0-9])?$`, n)
}
