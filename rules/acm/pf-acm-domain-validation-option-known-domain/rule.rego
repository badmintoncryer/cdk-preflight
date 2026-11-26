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
	_pf_acmdvo_forwarded(o)
	d := object.get(o, "DomainName", null)
	_pf_acm_lit(d)
	not d in names
}

# CloudFormation hands an entry to RequestCertificate only when it carries ValidationDomain. An entry
# with only HostedZoneId is the handler's own instruction for where to write the validation record, and
# one that names a domain the certificate does not ask for is simply unused: bench 2026-11-26 us-east-1,
# DomainName cdkpf-dvo-diag.appnao.com with a second HostedZoneId-only entry for other-dvo-diag.appnao.com
# -> CREATE_COMPLETE. An entry with both is rejected for that reason instead ("You can only have value for
# validationDomain or HostedZoneId but not both."), and one with neither for a null ValidationDomain.
_pf_acmdvo_forwarded(o) if {
	object.get(o, "ValidationDomain", "__pf_absent") != "__pf_absent"
	object.get(o, "HostedZoneId", "__pf_absent") == "__pf_absent"
}
