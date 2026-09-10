package cdk_preflight

import rego.v1

# Route 53 Resolver / Route 53 Profiles で共有するヘルパー。診断は出さない。
# 生のプロパティを見るので Ref/GetAtt はマーカー（{"__kind","__ref"}）のままで、
# is_string ガードがユーザーのリテラルだけを通す。

_pf_r53r_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

_pf_r53r_get(o, k) := v if {
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_r53r_has(o, k) if {
	_pf_r53r_get(o, k)
}

_pf_r53r_str(o, k) := v if {
	v := _pf_r53r_get(o, k)
	is_string(v)
}

_pf_r53r_num(o, k) := v if {
	v := _pf_r53r_get(o, k)
	is_number(v)
}

_pf_r53r_arr(o, k) := v if {
	v := _pf_r53r_get(o, k)
	is_array(v)
}

# Ref / GetAtt のマーカーが指す論理 ID。
_pf_r53r_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

_pf_r53r_refk(o, k) := r if {
	r := _pf_r53r_ref(_pf_r53r_get(o, k))
}

# 同一テンプレート内の <type> を指しているときだけ論理 ID を返す。
_pf_r53r_target(o, k, type) := r if {
	r := _pf_r53r_refk(o, k)
	r in resources_of_type(type)
}

# 参照でもリテラルでも「同じものを指しているか」を比べられる鍵。
_pf_r53r_key(o, k) := sprintf("ref:%s", [_pf_r53r_refk(o, k)])

_pf_r53r_key(o, k) := sprintf("lit:%s", [_pf_r53r_str(o, k)])

_pf_r53r_ipv4(s) if {
	regex.match(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`, s)
}

_pf_r53r_ipv6(s) if {
	contains(s, ":")
	regex.match(`^[0-9A-Fa-f:.]+$`, s)
	count(s) >= 2
	count(s) <= 39
}

# --- ResolverEndpoint ----------------------------------------------------

_pf_r53r_ips(p) := v if {
	v := _pf_r53r_arr(p, "IpAddresses")
}

# 実効プロトコル。省略時の既定は Do53 の 1 つだけ。
_pf_r53r_protos(p) := s if {
	s := {x | some x in _pf_r53r_arr(p, "Protocols"); is_string(x)}
	count(s) > 0
}

_pf_r53r_protos(p) := {"Do53"} if {
	not _pf_r53r_has(p, "Protocols")
}

# IpAddresses[] が参照する、同一テンプレート内のサブネットの論理 ID。
_pf_r53r_subnets(p) := [s |
	some ip in _pf_r53r_ips(p)
	s := _pf_r53r_target(ip, "SubnetId", "AWS::EC2::Subnet")
]

# ResolverRule が参照する、同一テンプレート内の ResolverEndpoint の論理 ID。
_pf_r53r_endpoint_of(p) := e if {
	e := _pf_r53r_target(p, "ResolverEndpointId", "AWS::Route53Resolver::ResolverEndpoint")
}

# --- FirewallRuleGroup ---------------------------------------------------

_pf_r53r_frules(name) := rs if {
	rs := _pf_r53r_arr(_pf_r53r_props(name), "FirewallRules")
}

# ルールがマッチ対象をどれで指定しているか（3 つは相互排他）。
_pf_r53r_match_keys := {"FirewallDomainListId", "DnsThreatProtection", "FirewallRuleType"}

_pf_r53r_match_used(r) := {k | some k in _pf_r53r_match_keys; _pf_r53r_has(r, k)}

_pf_r53r_qtypes := {"A", "AAAA", "CAA", "CNAME", "DS", "MX", "NAPTR", "NS", "PTR", "SOA", "SPF", "SRV", "TXT"}

# --- ARN の形（リテラルのときだけ見る。リージョン/アカウントは判定に使わない） ----

_pf_r53r_arn_service(s) := svc if {
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
	svc := parts[2]
}

_pf_r53r_arn_kind(s) := kind if {
	svc := _pf_r53r_arn_service(s)
	parts := split(s, ":")
	tail := concat(":", array.slice(parts, 5, count(parts)))
	kind := sprintf("%s:%s", [svc, split(tail, "/")[0]])
}

# DNS Firewall / Profiles の優先度。予約帯は 100 以下と 9900 以上（両端とも予約）。
_pf_r53r_outside_101_9899(v) if {
	v <= 100
}

_pf_r53r_outside_101_9899(v) if {
	v >= 9900
}

# ResourceProperties（JSON 文字列）の priority。キーの大文字小文字は API が両方受ける。
_pf_r53r_rp_priority(s) := v if {
	o := json.unmarshal(s)
	some k in ["priority", "Priority"]
	v := object.get(o, k, null)
	is_number(v)
}

# 同一テンプレート内のリソースが Profile から見てどの種類か。
_pf_r53r_res_kind(t) := "firewall-rule-group" if {
	t in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
}

_pf_r53r_res_kind(t) := "resolver-rule" if {
	t in resources_of_type("AWS::Route53Resolver::ResolverRule")
}

_pf_r53r_res_kind(t) := "hostedzone" if {
	t in resources_of_type("AWS::Route53::HostedZone")
}

_pf_r53r_res_kind(t) := "vpc-endpoint" if {
	t in resources_of_type("AWS::EC2::VPCEndpoint")
}

_pf_r53r_res_kind(t) := "resolver-query-log-config" if {
	t in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfig")
}

_pf_r53r_pra_kind(p) := k if {
	k := _pf_r53r_res_kind(_pf_r53r_refk(p, "ResourceArn"))
}

_pf_r53r_pra_kind(p) := k if {
	ak := _pf_r53r_arn_kind(_pf_r53r_str(p, "ResourceArn"))
	k := split(ak, ":")[1]
}

# query logging 関連付けの送信先タイプ。同一テンプレート内の config を辿る。
_pf_r53r_qlca_dest(p) := svc if {
	c := _pf_r53r_target(p, "ResolverQueryLogConfigId", "AWS::Route53Resolver::ResolverQueryLoggingConfig")
	q := _pf_r53r_props(c)
	svc := _pf_r53r_arn_service(_pf_r53r_str(q, "DestinationArn"))
}

_pf_r53r_qlca_dest(p) := svc if {
	c := _pf_r53r_target(p, "ResolverQueryLogConfigId", "AWS::Route53Resolver::ResolverQueryLoggingConfig")
	q := _pf_r53r_props(c)
	t := _pf_r53r_refk(q, "DestinationArn")
	svc := _pf_r53r_dest_svc(t)
}

_pf_r53r_qlca_dest(p) := "unknown" if {
	not _pf_r53r_target(p, "ResolverQueryLogConfigId", "AWS::Route53Resolver::ResolverQueryLoggingConfig")
}

_pf_r53r_dest_svc(t) := "logs" if {
	t in resources_of_type("AWS::Logs::LogGroup")
}

_pf_r53r_dest_svc(t) := "s3" if {
	t in resources_of_type("AWS::S3::Bucket")
}

_pf_r53r_dest_svc(t) := "firehose" if {
	t in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
}
