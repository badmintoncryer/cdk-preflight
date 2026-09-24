package cdk_preflight

import rego.v1

# AWS Certificate Manager (AWS::CertificateManager::*) のルールで共有するヘルパー。
# 診断は出さない。

# ユーザーが書いたリテラル文字列だけを通す。Ref / Fn::GetAtt はマーカー（resolve() が
# 論理 ID を返す）、`{{resolve:` は CloudFormation が実行時に解く動的参照で、どちらも
# 中身を検査できない。
_pf_acm_lit(s) if {
	is_string(s)
	not input.resources[s]
	not startswith(s, "{{resolve:")
}

_pf_acm_dvos(name) := [o |
	some item in flatten_list(name, "Properties.DomainValidationOptions")
	o := item.value
	is_object(o)
]

# 証明書が名乗る FQDN の集合（DomainName + SubjectAlternativeNames のリテラル）。
_pf_acm_names(name) := {d |
	some p in ["Properties.DomainName"]
	d := resolve(name, p)
	_pf_acm_lit(d)
} | {d |
	some item in flatten_list(name, "Properties.SubjectAlternativeNames")
	d := item.value
	_pf_acm_lit(d)
}

# ValidationDomain は「同じか上位ドメイン」でなければならない。
_pf_acm_covers(sup, dom) if sup == dom

_pf_acm_covers(sup, dom) if endswith(dom, concat("", [".", sup]))

# ValidationMethod を省略するとメール検証になる（EMAIL が既定）。resolve() は欠落で
# undefined なので、肯定形を書いて否定する（AGENTS.md の resolve() != の罠）。
_pf_acm_nonemail(name) if resolve(name, "Properties.ValidationMethod") in {"DNS", "HTTP"}

# 欠落は前処理済みドキュメントで証明する。_pf_acm_lit はマーカー（Ref / GetAtt）を落とすので、
# これで「無い」を判定すると `CertificateAuthorityArn: !GetAtt CA.Arn` を「公開証明書」と読み違える。
_pf_acm_private_ca(name) if {
	props := object.get(input.resources[name], "properties", {})
	is_object(props)
	object.get(props, "CertificateAuthorityArn", "__pf_absent") != "__pf_absent"
}
