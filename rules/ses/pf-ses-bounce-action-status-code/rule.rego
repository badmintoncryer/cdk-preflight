package cdk_preflight

import rego.v1

# SES が受ける拡張ステータスコードは class 4 か 5 で、subject も detail も 1 桁
# （実測 2026-09-24: 4.4.7 / 5.1.1 / 5.9.9 は 200、2.0.0 / 5.1 / 5.1.1.1 / 5.1.10 /
# 5.7.26 / 5.7.99 / 4.7.26 / 5.10.1 / 9.9 / 10.1.1 は拒否）。5.7.26 は RFC 3463 に実在する
# コードだが SES は受けないので、1 桁という読みは RFC ではなくサービスのもの。
# SmtpReplyCode とは独立した検査で、どちらも Sender の検証より先に走る。
violation contains make_diag_full("pf-ses-bounce-action-status-code", "ERROR", name,
	sprintf("Properties.Rule.Actions[%d].BounceAction.StatusCode", [i]),
	sprintf("StatusCode '%v' is not an RFC 3463 status code SES accepts; the stack fails with \"Invalid status code: %v\"", [c, c]),
	"Use a status code of the form 4.x.y or 5.x.y with single-digit subject and detail, such as 5.1.1",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_BounceAction.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRule")
	some [i, b] in _pf_sesrx_bounce(name)
	c := object.get(b, "StatusCode", null)
	_pf_ses_lit(c)
	not regex.match(`^[45]\.[0-9]\.[0-9]$`, c)
}
