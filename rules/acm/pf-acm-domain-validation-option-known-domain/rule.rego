package cdk_preflight

import rego.v1

# DomainValidationOptions は証明書が名乗る FQDN ごとの検証設定なので、その FQDN は
# DomainName か SubjectAlternativeNames のどれかでなければならない。スキーマは
# 2 つのリストの関係を見ない。
# DomainName か SubjectAlternativeNames のどれかが不透明（Ref / GetAtt / 動的参照、あるいは
# リスト自体が参照）なら、証明書が名乗る名前の集合が埋まらない。埋まらない集合に対する
# 「入っていない」は証明になっていないので判定を降りる。
_pf_acmdvo_opaque(name) if {
	sans := object.get(object.get(input.resources[name], "properties", {}), "SubjectAlternativeNames", [])
	not is_array(sans)
}

_pf_acmdvo_opaque(name) if {
	some item in flatten_list(name, "Properties.SubjectAlternativeNames")
	not _pf_acm_lit(item.value)
}

violation contains make_diag_full("pf-acm-domain-validation-option-known-domain", "ERROR", name,
	"Properties.DomainValidationOptions",
	sprintf("DomainValidationOptions names '%v', which is neither DomainName nor a SubjectAlternativeName; the certificate request fails with \"The domain specified in ValidationOptions, %v, is not the PrimaryDomain or part of SubjectAlternativeNames.\"", [d, d]),
	"Name the certificate's own DomainName (or one of its SubjectAlternativeNames) in each DomainValidationOptions entry",
	"https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html") if {
	some name in resources_of_type("AWS::CertificateManager::Certificate")
	_pf_acm_lit(resolve(name, "Properties.DomainName"))
	not _pf_acmdvo_opaque(name)
	names := _pf_acm_names(name)
	some o in _pf_acm_dvos(name)
	d := object.get(o, "DomainName", null)
	_pf_acm_lit(d)
	not d in names
}
