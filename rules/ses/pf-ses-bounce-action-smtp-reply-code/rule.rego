package cdk_preflight

import rego.v1

# SES が受けるのは 4xx / 5xx の 3 桁だけ（実測 2026-09-24: 421 / 450 / 504 / 550 / 599 は
# 200、45 / 99 / 100 / 250 / 354 / 399 / 600 / 999 / 4500 は拒否）。スキーマは pattern を
# 持たない。SMTP として正しい 250 や 354 も、バウンスの返答ではないので通らない。
violation contains make_diag_full("pf-ses-bounce-action-smtp-reply-code", "ERROR", name,
	sprintf("Properties.Rule.Actions[%d].BounceAction.SmtpReplyCode", [i]),
	sprintf("SmtpReplyCode '%v' is not a 4xx or 5xx three-digit reply code; the stack fails with \"Invalid SMTP reply code: %v\"", [c, c]),
	"Use a three-digit SMTP reply code that starts with 4 or 5, such as 550",
	"https://docs.aws.amazon.com/ses/latest/APIReference/API_BounceAction.html") if {
	some name in resources_of_type("AWS::SES::ReceiptRule")
	some [i, b] in _pf_sesrx_bounce(name)
	c := object.get(b, "SmtpReplyCode", null)
	_pf_ses_lit(c)
	not regex.match(`^[45][0-9]{2}$`, c)
}
