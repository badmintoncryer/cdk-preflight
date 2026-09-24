package cdk_preflight

import rego.v1

# ValidationDomain はメール検証でだけ意味を持つ（WHOIS と admin@ 等の宛先を引く
# ドメイン）。ACM は「同じか上位ドメイン」しか受けない。ValidationMethod を省略すると
# メール検証になるので、肯定形 _pf_acm_nonemail を否定して欠落もこちら側に寄せる。
_pf_acmvds_target(name, o) := d if {
	d := object.get(o, "DomainName", null)
	_pf_acm_lit(d)
}

# エントリが DomainName を書いていないときだけ証明書の DomainName に落ちる。
# 「リテラルでない」で落ちると、Ref で書かれたエントリを別のドメインと突き合わせてしまう。
_pf_acmvds_target(name, o) := d if {
	object.get(o, "DomainName", "__pf_absent") == "__pf_absent"
	d := resolve(name, "Properties.DomainName")
	_pf_acm_lit(d)
}

violation contains make_diag_full("pf-acm-validation-domain-superdomain", "ERROR", name,
	"Properties.DomainValidationOptions",
	sprintf("ValidationDomain '%v' is not '%v' nor a superdomain of it; the certificate request fails with \"The validation domain, %v, must be a superdomain of the requested domain, %v.\"", [vd, dom, vd, dom]),
	sprintf("Set ValidationDomain to %v or to one of its parent domains, or switch to ValidationMethod: DNS", [dom]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-certificatemanager-certificate-domainvalidationoption.html") if {
	some name in resources_of_type("AWS::CertificateManager::Certificate")
	not _pf_acm_nonemail(name)
	some o in _pf_acm_dvos(name)
	vd := object.get(o, "ValidationDomain", null)
	_pf_acm_lit(vd)
	dom := _pf_acmvds_target(name, o)
	not _pf_acm_covers(vd, dom)
}
