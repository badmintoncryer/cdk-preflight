package cdk_preflight

import rego.v1

# AWS Cloud Map (AWS::ServiceDiscovery::*) のルールで共有するヘルパー。診断は出さない。
# 生のプロパティを読むので Ref / Fn::GetAtt はマーカー（{"__kind","__ref"}）のまま残り、
# is_string ガードがユーザーの書いたリテラルだけを通す。namespace への 1 ホップだけは
# resolve() を使う（Ref も Fn::GetAtt .Id も同じ論理 ID を返す)。
# リテラルの "ns-xxxx" を書かれた場合は参照先が引けないので、ルールは黙る設計。

_pf_sd_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

_pf_sd_get(o, k) := v if {
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_sd_str(name, k) := v if {
	v := _pf_sd_get(_pf_sd_props(name), k)
	is_string(v)
}

_pf_sd_namespace_types := ["AWS::ServiceDiscovery::HttpNamespace", "AWS::ServiceDiscovery::PublicDnsNamespace", "AWS::ServiceDiscovery::PrivateDnsNamespace"]

# 同一テンプレート内の namespace の論理 ID（3 型すべて / DNS 型だけ）。
_pf_sd_namespaces := {n |
	some t in _pf_sd_namespace_types
	some n in resources_of_type(t)
}

_pf_sd_dns_namespaces := {n |
	some t in ["AWS::ServiceDiscovery::PublicDnsNamespace", "AWS::ServiceDiscovery::PrivateDnsNamespace"]
	some n in resources_of_type(t)
}

# Service が指す namespace の論理 ID。NamespaceId と DnsConfig.NamespaceId（旧形式）の
# 両方を見る。集合で返すのは、両方が別の namespace を指したときに関数の出力が衝突して
# 評価エラーになるのを避けるため。
_pf_sd_ns_ids(svc) := {ns |
	some p in ["Properties.NamespaceId", "Properties.DnsConfig.NamespaceId"]
	ns := resolve(svc, p)
	ns in _pf_sd_namespaces
}

_pf_sd_dnsconfig(svc) := c if {
	c := object.get(_pf_sd_props(svc), "DnsConfig", null)
	is_object(c)
}

_pf_sd_records(svc) := [r |
	some r in object.get(_pf_sd_dnsconfig(svc), "DnsRecords", [])
	is_object(r)
]

_pf_sd_record_types(svc) := [t |
	some r in _pf_sd_records(svc)
	t := object.get(r, "Type", null)
	is_string(t)
]

# RoutingPolicy を省略したときの既定は MULTIVALUE。
_pf_sd_routing(svc) := p if {
	p := object.get(_pf_sd_dnsconfig(svc), "RoutingPolicy", "MULTIVALUE")
	is_string(p)
}

_pf_sd_healthcheck(svc) := c if {
	c := object.get(_pf_sd_props(svc), "HealthCheckConfig", null)
	is_object(c)
}

# ^(?!arn:)[!-~]{1,N}$ のうち RE2 で書けない先読みを分けたもの（長さは各ルールが見る）。
_pf_sd_printable_ascii(s) if {
	regex.match(`^[!-~]+$`, s)
	not startswith(s, "arn:")
}
