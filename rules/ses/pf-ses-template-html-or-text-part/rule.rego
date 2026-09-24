package cdk_preflight

import rego.v1

# SubjectPart だけが Required: Yes なので、スキーマは本文の無いテンプレートを通す。
_pf_sesthtp_part(name) if {
	some k in ["HtmlPart", "TextPart"]
	tpl := resolve(name, "Properties.Template")
	is_object(tpl)
	object.get(tpl, k, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ses-template-html-or-text-part", "ERROR", name,
	"Properties.Template",
	"the template has neither HtmlPart nor TextPart; the template create fails with \"Template must specify at least one of the parts.\"",
	"Add an HtmlPart, a TextPart, or both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-template.html") if {
	some name in resources_of_type("AWS::SES::Template")
	tpl := resolve(name, "Properties.Template")
	is_object(tpl)
	not _pf_sesthtp_part(name)
}
