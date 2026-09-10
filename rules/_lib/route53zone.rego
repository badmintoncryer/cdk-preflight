package cdk_preflight

import rego.v1

# Route 53 のゾーン側リソース（HostedZone / HealthCheck / CidrCollection /
# KeySigningKey / DNSSEC）で共有するヘルパー。診断は出さない。
# 生のプロパティを見るので Ref/GetAtt はマーカー（{"__kind","__ref"}）のままで、
# is_string ガードがユーザーのリテラルだけを通す。

_pf_r53z_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

_pf_r53z_get(o, k) := v if {
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_r53z_has(o, k) if {
	_pf_r53z_get(o, k)
}

_pf_r53z_str(o, k) := v if {
	v := _pf_r53z_get(o, k)
	is_string(v)
}

# Fn::GetAtt <logical>.<attr> のマーカーが指す論理 ID。
_pf_r53z_getatt(v, attr) := r if {
	is_object(v)
	object.get(v, "__kind", "") == sprintf("getatt:%s", [attr])
	r := object.get(v, "__ref", null)
	is_string(r)
}

# リージョン名の形（列挙は AWS が増やすたびに誤検知になるので形だけ見る）。
_pf_r53z_region_shape(r) if {
	regex.match(`^[a-z]+(-[a-z]+)+-[0-9]$`, r)
}

# --- HealthCheck ---------------------------------------------------------

_pf_r53z_hcc(name) := c if {
	c := object.get(_pf_r53z_props(name), "HealthCheckConfig", null)
	is_object(c)
}

_pf_r53z_hc_types := {"CALCULATED", "CLOUDWATCH_METRIC", "HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP", "RECOVERY_CONTROL"}

# エンドポイントを実際に叩く型。IPAddress/FullyQualifiedDomainName を持てるのはこれだけ。
_pf_r53z_endpoint_types := {"HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP"}

_pf_r53z_http_types := {"HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH"}

_pf_r53z_strmatch_types := {"HTTP_STR_MATCH", "HTTPS_STR_MATCH"}

_pf_r53z_https_types := {"HTTPS", "HTTPS_STR_MATCH"}

# ヘルスチェッカーを配置できるリージョン（8 個で固定、API の閉じた列挙）。
_pf_r53z_checker_regions := {"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"}

# CALCULATED の子として指定された、同一テンプレート内のヘルスチェックの論理 ID。
_pf_r53z_children(cfg) := [id |
	some v in object.get(cfg, "ChildHealthChecks", [])
	id := object.get(v, "__ref", null)
	is_string(id)
	id in resources_of_type("AWS::Route53::HealthCheck")
]

# CLOUDWATCH_METRIC ヘルスチェックが監視する、同一テンプレート内のアラームの論理 ID。
# AlarmIdentifier.Name は Ref（マーカー）でもリテラルの AlarmName でも受ける。
_pf_r53z_alarm_of(cfg) := alarm if {
	ai := object.get(cfg, "AlarmIdentifier", null)
	is_object(ai)
	n := object.get(ai, "Name", null)
	some alarm in resources_of_type("AWS::CloudWatch::Alarm")
	_pf_r53z_alarm_named(alarm, n)
}

_pf_r53z_alarm_named(alarm, n) if {
	object.get(n, "__ref", null) == alarm
}

_pf_r53z_alarm_named(alarm, n) if {
	is_string(n)
	n == object.get(_pf_r53z_props(alarm), "AlarmName", null)
}

# --- HostedZone ----------------------------------------------------------

_pf_r53z_zname(name) := trim_suffix(lower(n), ".") if {
	n := object.get(_pf_r53z_props(name), "Name", null)
	is_string(n)
}

_pf_r53z_vpcs(name) := v if {
	v := object.get(_pf_r53z_props(name), "VPCs", null)
	is_array(v)
}

# private zone に紐づく VPC の識別子（Ref でもリテラルの vpc-xxxx でも同じキーにする）。
_pf_r53z_vpcidset(name) := {id |
	some v in _pf_r53z_vpcs(name)
	is_object(v)
	id := _pf_r53z_vpcid(v)
}

_pf_r53z_vpcid(v) := id if {
	x := object.get(v, "VPCId", null)
	id := object.get(x, "__ref", null)
	is_string(id)
}

_pf_r53z_vpcid(v) := id if {
	id := object.get(v, "VPCId", null)
	is_string(id)
}

_pf_r53z_qlog_arn(name) := a if {
	q := object.get(_pf_r53z_props(name), "QueryLoggingConfig", null)
	is_object(q)
	a := object.get(q, "CloudWatchLogsLogGroupArn", null)
	is_string(a)
}

# --- CidrCollection ------------------------------------------------------

# [ロケーションの添字, CidrList 内の添字, CIDR 文字列] の一覧。
_pf_r53z_cidrs(name) := [[loc.index, i, c] |
	some loc in flatten_list(name, "Properties.Locations")
	is_object(loc.value)
	some i, c in object.get(loc.value, "CidrList", [])
	is_string(c)
]

_pf_r53z_prefix(c) := to_number(p) if {
	parts := split(c, "/")
	count(parts) == 2
	p := parts[1]
}

_pf_r53z_is_v6(c) if {
	contains(c, ":")
}

# --- KeySigningKey / DNSSEC ---------------------------------------------

# KSK / DNSSEC が紐づく、同一テンプレート内のホストゾーンの論理 ID。
_pf_r53z_zone_of(name) := z if {
	z := resolve(name, "Properties.HostedZoneId")
	z in resources_of_type("AWS::Route53::HostedZone")
}

# KSK が参照する、同一テンプレート内の KMS キーの論理 ID。
_pf_r53z_key_of(name) := k if {
	k := resolve(name, "Properties.KeyManagementServiceArn")
	k in resources_of_type("AWS::KMS::Key")
}

_pf_r53z_stmts(k) := s if {
	pol := object.get(_pf_r53z_props(k), "KeyPolicy", null)
	is_object(pol)
	s := object.get(pol, "Statement", [])
	is_array(s)
}

_pf_r53z_svc(st) := p if {
	pr := object.get(st, "Principal", null)
	is_object(pr)
	p := object.get(pr, "Service", null)
}

_pf_r53z_svc_is(st, svc) if {
	_pf_r53z_svc(st) == svc
}

_pf_r53z_svc_is(st, svc) if {
	l := _pf_r53z_svc(st)
	is_array(l)
	svc in l
}

_pf_r53z_alist(st) := [a] if {
	a := object.get(st, "Action", null)
	is_string(a)
}

_pf_r53z_alist(st) := a if {
	a := object.get(st, "Action", null)
	is_array(a)
}

_pf_r53z_dnssec_principal := "dnssec-route53.amazonaws.com"

# キーポリシーが DNSSEC のサービスプリンシパルに Allow を与えているか。
_pf_r53z_key_grants(k) if {
	some st in _pf_r53z_stmts(k)
	object.get(st, "Effect", "") == "Allow"
	_pf_r53z_svc_is(st, _pf_r53z_dnssec_principal)
}

_pf_r53z_signing_actions(k) := {a |
	some st in _pf_r53z_stmts(k)
	object.get(st, "Effect", "") == "Allow"
	_pf_r53z_svc_is(st, _pf_r53z_dnssec_principal)
	some a in _pf_r53z_alist(st)
}

_pf_r53z_allows(acts, a) if {
	a in acts
}

_pf_r53z_allows(acts, _) if {
	"kms:*" in acts
}

_pf_r53z_missing_actions(k) := {a |
	some a in {"kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"}
	not _pf_r53z_allows(_pf_r53z_signing_actions(k), a)
}

# 同じゾーンに付いている KSK の論理 ID。
_pf_r53z_ksks_of(z) := [k |
	some k in resources_of_type("AWS::Route53::KeySigningKey")
	_pf_r53z_zone_of(k) == z
]

_pf_r53z_dnssec_keyspec(ks, ku) if {
	ks == "ECC_NIST_P256"
	ku == "SIGN_VERIFY"
}
