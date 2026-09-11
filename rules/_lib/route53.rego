package cdk_preflight

import rego.v1

# Route 53 のレコード系ルールの共有ヘルパー。診断は出さない。
#
# レコードセットは 2 つの形で現れる: AWS::Route53::RecordSet リソースそのものと、
# AWS::Route53::RecordSetGroup の Properties.RecordSets の各要素。どちらも
# 「プロパティのオブジェクト」に正規化して、以下のヘルパーはすべてその rs を受け取る。
# 生のオブジェクトを見るので Ref/GetAtt はマーカー（{"__kind","__ref"}）のままで、
# is_string ガードがユーザーのリテラルだけを通す。

_pf_r53lib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_r53lib_get(rs, k) := v if {
	v := object.get(rs, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_r53lib_has(rs, k) if {
	_pf_r53lib_get(rs, k)
}

_pf_r53lib_str(rs, k) := v if {
	v := _pf_r53lib_get(rs, k)
	is_string(v)
}

_pf_r53lib_num(rs, k) := to_number(_pf_r53lib_get(rs, k))

# 末尾ドットを落として小文字化した DNS 名。Route 53 は両者を同じ名前として扱う。
_pf_r53lib_norm(n) := trim_suffix(lower(n), ".")

_pf_r53lib_name(rs) := _pf_r53lib_norm(_pf_r53lib_str(rs, "Name"))

_pf_r53lib_type(rs) := _pf_r53lib_str(rs, "Type")

# Name と Type が両方リテラルのときだけ定義される、レコードセットのグループキー。
_pf_r53lib_key(rs) := sprintf("%s|%s", [_pf_r53lib_name(rs), _pf_r53lib_type(rs)])

_pf_r53lib_policy_props := {"Weight", "Region", "Failover", "GeoLocation", "GeoProximityLocation", "CidrRoutingConfig", "MultiValueAnswer"}

# 指定されているルーティングポリシー用プロパティの集合。空集合なら simple。
_pf_r53lib_kinds(rs) := {p |
	some p in _pf_r53lib_policy_props
	_pf_r53lib_has(rs, p)
}

_pf_r53lib_rrs(rs) := a if {
	a := _pf_r53lib_get(rs, "ResourceRecords")
	is_array(a)
}

# リテラル文字列の値だけ。intrinsic 経由の値はマーカーなので落ちる。
_pf_r53lib_vals(rs) := [v |
	some v in _pf_r53lib_rrs(rs)
	is_string(v)
]

# 空白区切りのフィールド（連続空白は潰す）。
_pf_r53lib_fields(v) := [f |
	some f in split(v, " ")
	f != ""
]

_pf_r53lib_quoted(f) if {
	startswith(f, "\"")
	endswith(f, "\"")
	count(f) >= 2
}

_pf_r53lib_alias(rs) := a if {
	a := _pf_r53lib_get(rs, "AliasTarget")
	is_object(a)
}

_pf_r53lib_alias_dns(rs) := _pf_r53lib_norm(d) if {
	d := object.get(_pf_r53lib_alias(rs), "DNSName", null)
	is_string(d)
}

_pf_r53lib_alias_zoneid(rs) := z if {
	z := object.get(_pf_r53lib_alias(rs), "HostedZoneId", null)
	is_string(z)
}

# Ref / GetAtt マーカーが指す論理 ID。
_pf_r53lib_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

# alias 先が同一テンプレート内の HostedZone（＝このスタックで新規に作られるゾーン）
# のとき、その論理 ID。
_pf_r53lib_alias_ownzone(rs) := z if {
	z := _pf_r53lib_ref(object.get(_pf_r53lib_alias(rs), "HostedZoneId", null))
	z in resources_of_type("AWS::Route53::HostedZone")
}

_pf_r53lib_zone_name(logical) := _pf_r53lib_norm(n) if {
	n := resolve(logical, "Properties.Name")
	is_string(n)
}

# private hosted zone（VPCs が 1 件以上）
_pf_r53lib_private_zone(logical) if {
	count(flatten_list(logical, "Properties.VPCs")) > 0
}

# レコードが属するゾーンの論理 ID（HostedZoneId が同一テンプレートのゾーンを指すとき）。
_pf_r53lib_own_zone(rs) := z if {
	z := _pf_r53lib_ref(_pf_r53lib_get(rs, "HostedZoneId"))
	z in resources_of_type("AWS::Route53::HostedZone")
}

# name が suffix ゾーンの内側にあるか（apex を含む）。
_pf_r53lib_within(name, zone) if {
	name == zone
}

_pf_r53lib_within(name, zone) if {
	endswith(name, concat("", [".", zone]))
}

# テンプレートが作るレコードセットの "name|type" キーと name の集合。
# 同一ゾーン内 alias の参照先が本当にテンプレートにあるかを見るのに使う。
# ネストしたコンプリヘンションは 1 本に書けない（エンジンの方言）ので段で分ける。

_pf_r53lib_gkeys(g) := {_pf_r53lib_key(it.value) |
	some it in flatten_list(g, "Properties.RecordSets")
}

_pf_r53lib_gnames(g) := {_pf_r53lib_name(it.value) |
	some it in flatten_list(g, "Properties.RecordSets")
}

_pf_r53lib_skeys := {_pf_r53lib_key(_pf_r53lib_props(r)) |
	some r in resources_of_type("AWS::Route53::RecordSet")
}

_pf_r53lib_snames := {_pf_r53lib_name(_pf_r53lib_props(r)) |
	some r in resources_of_type("AWS::Route53::RecordSet")
}

_pf_r53lib_gkeys_all := union({_pf_r53lib_gkeys(g) |
	some g in resources_of_type("AWS::Route53::RecordSetGroup")
})

_pf_r53lib_gnames_all := union({_pf_r53lib_gnames(g) |
	some g in resources_of_type("AWS::Route53::RecordSetGroup")
})

_pf_r53lib_keys := union({_pf_r53lib_skeys, _pf_r53lib_gkeys_all})

_pf_r53lib_names := union({_pf_r53lib_snames, _pf_r53lib_gnames_all})

# 複数ルールが共有する定数・ヘルパー（同一定義の重複を避けるためここに置く）。

_pf_r53_regions := {
	"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2",
	"ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1", "cn-north-1", "cn-northwest-1", "eu-central-1",
	"eu-central-2", "eu-isoe-west-1", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3", "eusc-de-east-1", "il-central-1",
	"me-central-1", "me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-1", "us-iso-east-1", "us-iso-west-1",
	"us-isob-east-1", "us-isob-west-1", "us-isof-east-1", "us-isof-south-1", "us-west-1", "us-west-2",
}

_pf_r53_svcb_keys := {"alpn", "dohpath", "ech", "ipv4hint", "ipv6hint", "no-default-alpn", "ohttp", "port"}

_pf_r53_svcb_valued := {"alpn", "dohpath", "ech", "ipv4hint", "ipv6hint", "port"}

_pf_r53_svcb_keyset(f) := {k |
	some i in numbers.range(2, count(f) - 1)
	k := split(f[i], "=")[0]
}
