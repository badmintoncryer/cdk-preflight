package cdk_preflight

import rego.v1

# Shared helpers for the ELBv2 rules. The three attribute properties
# (LoadBalancerAttributes / TargetGroupAttributes / ListenerAttributes) are
# [{Key, Value}] string pairs, so every value arrives as a string and every
# lookup goes through _pf_elb_attrset (a set, so a duplicated key never turns
# into an object-comprehension conflict that silences the other rules).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_elb_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_elb_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absence has to be proven against the raw document: resolve() cannot tell
# "absent" from "unresolvable".
_pf_elb_absent(name, key) if {
	object.get(object.get(input.resources[name], "properties", {}), key, "__pf_absent") == "__pf_absent"
}

_pf_elb_oget(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_elb_ohas(o, k) if {
	_pf_elb_oget(o, k)
}

_pf_elb_get(name, k) := _pf_elb_oget(_pf_elb_props(name), k)

_pf_elb_has(name, k) if {
	not _pf_elb_absent(name, k)
}

_pf_elb_str(name, k) := v if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	is_string(v)
}

# Attribute values are strings; ordinary properties are numbers.
_pf_elb_num(v) := v if is_number(v)

_pf_elb_num(v) := n if {
	is_string(v)
	regex.match(`^-?[0-9]+$`, v)
	n := to_number(v)
}

# A Ref that survives inside a list is {"__ref": "<logical id>"} (flatten_list
# does not resolve it the way resolve() does on a scalar property).
_pf_elb_ref(v) := v if is_string(v)

_pf_elb_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

_pf_elb_lbs := resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")

_pf_elb_tgs := resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")

_pf_elb_listeners := resources_of_type("AWS::ElasticLoadBalancingV2::Listener")

# application unless stated otherwise (the CFN default).
_pf_elb_lbtype(lb) := t if {
	t := object.get(_pf_elb_props(lb), "Type", "application")
	is_string(t)
}

# The load balancer a listener points at, only when it lives in this template.
_pf_elb_lb_of(listener) := lb if {
	lb := resolve(listener, "Properties.LoadBalancerArn")
	lb in _pf_elb_lbs
}

_pf_elb_listener_lbtype(listener) := _pf_elb_lbtype(_pf_elb_lb_of(listener))

_pf_elb_listener_of(rule) := l if {
	l := resolve(rule, "Properties.ListenerArn")
	l in _pf_elb_listeners
}

# Every value carried under one attribute key. Empty when the key is absent.
_pf_elb_attrset(name, prop, key) := {v |
	some it in flatten_list(name, sprintf("Properties.%s", [prop]))
	object.get(it.value, "Key", null) == key
	v := object.get(it.value, "Value", null)
}

_pf_elb_attrhas(name, prop, key) if {
	count(_pf_elb_attrset(name, prop, key)) > 0
}

# The single value of an attribute key, when it is written exactly once.
_pf_elb_attr(name, prop, key) := v if {
	s := _pf_elb_attrset(name, prop, key)
	count(s) == 1
	some v in s
}

_pf_elb_secure := {"HTTPS", "TLS"}

# LoadBalancerAttributes: which keys the service recognises per load balancer
# type. Common -> every type; the ALB/NLB pair adds logging and IGW/zonal
# shift; the rest are type-only.
_pf_elb_lbattr_common := {"deletion_protection.enabled", "load_balancing.cross_zone.enabled"}

_pf_elb_lbattr_shared := {
	"access_logs.s3.enabled", "access_logs.s3.bucket", "access_logs.s3.prefix",
	"ipv6.deny_all_igw_traffic", "zonal_shift.config.enabled",
}

_pf_elb_lbattr_alb := {
	"idle_timeout.timeout_seconds", "client_keep_alive.seconds",
	"connection_logs.s3.enabled", "connection_logs.s3.bucket", "connection_logs.s3.prefix",
	"health_check_logs.s3.enabled", "health_check_logs.s3.bucket", "health_check_logs.s3.prefix",
	"routing.http.desync_mitigation_mode", "routing.http.drop_invalid_header_fields.enabled",
	"routing.http.preserve_host_header.enabled", "routing.http.x_amzn_tls_version_and_cipher_suite.enabled",
	"routing.http.xff_client_port.enabled", "routing.http.xff_header_processing.mode",
	"routing.http2.enabled", "waf.fail_open.enabled",
}

_pf_elb_lbattr_nlb := {"dns_record.client_routing_policy", "secondary_ips.auto_assigned.per_subnet"}

_pf_elb_lbattr_for := {
	"application": (_pf_elb_lbattr_common | _pf_elb_lbattr_shared) | _pf_elb_lbattr_alb,
	"network": (_pf_elb_lbattr_common | _pf_elb_lbattr_shared) | _pf_elb_lbattr_nlb,
	"gateway": _pf_elb_lbattr_common,
}

_pf_elb_lbattr_known := (_pf_elb_lbattr_for.application | _pf_elb_lbattr_for.network) | _pf_elb_lbattr_for.gateway

# Every [{Key, Value}] pair of one attribute property, as {index, key, value}.
_pf_elb_pairs(name, prop) := [{"index": it.index, "key": k, "value": object.get(it.value, "Value", null)} |
	some it in flatten_list(name, sprintf("Properties.%s", [prop]))
	k := object.get(it.value, "Key", null)
	is_string(k)
]

# Attribute keys that only take "true" or "false".
_pf_elb_bool_key(k) if endswith(k, ".enabled")

_pf_elb_bool_key(k) if k == "ipv6.deny_all_igw_traffic"

_pf_elb_outside(v, lo, _) if v < lo

_pf_elb_outside(v, _, hi) if v > hi

_pf_elb_tgtype(tg) := t if {
	t := object.get(_pf_elb_props(tg), "TargetType", "instance")
	is_string(t)
}

# Matcher.HttpCode / Matcher.GrpcCode are "200", "200,202" or "200-299".
_pf_elb_codes(s) := [n |
	some part in split(s, ",")
	some b in split(part, "-")
	t := trim_space(b)
	regex.match(`^[0-9]+$`, t)
	n := to_number(t)
]

_pf_elb_hc_protocols := {"HTTP", "HTTPS", "TCP"}

_pf_elb_alb_protocols := {"HTTP", "HTTPS"}

# TargetGroupAttributes are scoped by the protocol family of the target group
# (a target group is created before it is attached to any load balancer).
_pf_elb_tgfamily(tg) := "lambda" if _pf_elb_tgtype(tg) == "lambda"

_pf_elb_tgfamily(tg) := f if {
	_pf_elb_tgtype(tg) != "lambda"
	p := object.get(_pf_elb_props(tg), "Protocol", "")
	f := _pf_elb_family_of[p]
}

_pf_elb_family_of := {
	"HTTP": "application", "HTTPS": "application",
	"TCP": "network", "TLS": "network", "UDP": "network",
	"TCP_UDP": "network", "QUIC": "network", "TCP_QUIC": "network",
	"GENEVE": "gateway",
}

_pf_elb_tgattr_common := {"deregistration_delay.timeout_seconds", "stickiness.enabled", "stickiness.type"}

_pf_elb_tgattr_shared := {
	"load_balancing.cross_zone.enabled",
	"target_group_health.dns_failover.minimum_healthy_targets.count",
	"target_group_health.dns_failover.minimum_healthy_targets.percentage",
	"target_group_health.unhealthy_state_routing.minimum_healthy_targets.count",
	"target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage",
}

_pf_elb_tgattr_alb := {
	"load_balancing.algorithm.type", "load_balancing.algorithm.anomaly_mitigation",
	"slow_start.duration_seconds", "stickiness.app_cookie.cookie_name",
	"stickiness.app_cookie.duration_seconds", "stickiness.lb_cookie.duration_seconds",
}

_pf_elb_tgattr_nlb := {
	"deregistration_delay.connection_termination.enabled", "preserve_client_ip.enabled",
	"proxy_protocol_v2.enabled", "target_health_state.unhealthy.connection_termination.enabled",
	"target_health_state.unhealthy.draining_interval_seconds",
}

_pf_elb_tgattr_gwlb := {
	"target_failover.on_deregistration", "target_failover.on_unhealthy",
	"send_tcp_reset.on_unhealthy.enabled", "send_tcp_reset.on_deregistration.enabled",
}

_pf_elb_tgattr_lambda := {"lambda.multi_value_headers.enabled"}

_pf_elb_tgattr_for := {
	"application": (_pf_elb_tgattr_common | _pf_elb_tgattr_shared) | _pf_elb_tgattr_alb,
	"network": (_pf_elb_tgattr_common | _pf_elb_tgattr_shared) | _pf_elb_tgattr_nlb,
	"gateway": _pf_elb_tgattr_common | _pf_elb_tgattr_gwlb,
	"lambda": _pf_elb_tgattr_common | _pf_elb_tgattr_lambda,
}

_pf_elb_tgattr_known := ((_pf_elb_tgattr_for.application | _pf_elb_tgattr_for.network) |
	_pf_elb_tgattr_for.gateway) | _pf_elb_tgattr_for.lambda

_pf_elb_region := r if {
	r := data.cdk_preflight.deploy_region
	is_string(r)
}

_pf_elb_arn_part(arn, i) := v if {
	is_string(arn)
	p := split(arn, ":")
	count(p) >= 6
	p[0] == "arn"
	v := p[i]
	v != ""
}

_pf_elb_arn_service(arn) := _pf_elb_arn_part(arn, 2)

_pf_elb_arn_region(arn) := _pf_elb_arn_part(arn, 3)

# The predefined security policies, from the ALB and NLB "security policies"
# tables (2026-09). ELBSecurityPolicy-2015-05 appears only in the NLB table.
_pf_elb_sslpolicy_nlb_only := {"ELBSecurityPolicy-2015-05"}

_pf_elb_sslpolicies := _pf_elb_sslpolicy_nlb_only | {
	"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-FS-1-2-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10", "ELBSecurityPolicy-FS-2018-06",
	"ELBSecurityPolicy-TLS-1-1-2017-01", "ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-TLS13-1-0-2021-06", "ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-1-2021-06", "ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext0-RFC9151-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04", "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-RFC9151-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP3-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP4-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-2021-06", "ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09", "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-RFC9151-FIPS-2023-07",
}

# An action list ends on one of these.
_pf_elb_routing_actions := {"forward", "redirect", "fixed-response"}

_pf_elb_action_config := {
	"ForwardConfig": "forward",
	"AuthenticateCognitoConfig": "authenticate-cognito",
	"AuthenticateOidcConfig": "authenticate-oidc",
	"RedirectConfig": "redirect",
	"FixedResponseConfig": "fixed-response",
}

_pf_elb_actions(name, prop) := flatten_list(name, sprintf("Properties.%s", [prop]))

# Actions live on two properties, so every action rule walks both.
_pf_elb_action_lists := [
	["AWS::ElasticLoadBalancingV2::Listener", "DefaultActions"],
	["AWS::ElasticLoadBalancingV2::ListenerRule", "Actions"],
]

_pf_elb_all_actions contains {"name": name, "prop": entry[1], "index": a.index, "value": a.value} if {
	some entry in _pf_elb_action_lists
	some name in resources_of_type(entry[0])
	some a in _pf_elb_actions(name, entry[1])
}

# The listener an action runs on (a rule's actions run on its listener).
_pf_elb_action_listener(name) := name if name in _pf_elb_listeners

_pf_elb_action_listener(name) := _pf_elb_listener_of(name) if {
	name in resources_of_type("AWS::ElasticLoadBalancingV2::ListenerRule")
}

_pf_elb_listener_proto(name) := object.get(_pf_elb_props(_pf_elb_action_listener(name)), "Protocol", "")

# The target groups a forward action spreads over.
_pf_elb_fwd_tgs(a) := tgs if {
	fc := object.get(a, "ForwardConfig", {})
	is_object(fc)
	tgs := object.get(fc, "TargetGroups", [])
	is_array(tgs)
}

# A target group in this template, from a TargetGroupTuple.
_pf_elb_tuple_tg(tg) := g if {
	g := _pf_elb_ref(object.get(tg, "TargetGroupArn", null))
	g in _pf_elb_tgs
}

_pf_elb_auth_configs := {"AuthenticateOidcConfig", "AuthenticateCognitoConfig"}

_pf_elb_true := {true, "true"}

# ListenerAttributes: the idle timeout is a Network/Gateway knob, the TCP reset
# a Gateway one, and everything else (mTLS header names, response headers) is
# Application only.
_pf_elb_lsattr_alb := {
	"routing.http.request.x_amzn_mtls_clientcert.header_name",
	"routing.http.request.x_amzn_mtls_clientcert_serial_number.header_name",
	"routing.http.request.x_amzn_mtls_clientcert_issuer.header_name",
	"routing.http.request.x_amzn_mtls_clientcert_subject.header_name",
	"routing.http.request.x_amzn_mtls_clientcert_validity.header_name",
	"routing.http.request.x_amzn_mtls_clientcert_leaf.header_name",
	"routing.http.request.x_amzn_tls_version.header_name",
	"routing.http.request.x_amzn_tls_cipher_suite.header_name",
	"routing.http.response.server.enabled",
	"routing.http.response.strict_transport_security.header_value",
	"routing.http.response.access_control_allow_origin.header_value",
	"routing.http.response.access_control_allow_methods.header_value",
	"routing.http.response.access_control_allow_headers.header_value",
	"routing.http.response.access_control_allow_credentials.header_value",
	"routing.http.response.access_control_expose_headers.header_value",
	"routing.http.response.access_control_max_age.header_value",
	"routing.http.response.content_security_policy.header_value",
	"routing.http.response.x_content_type_options.header_value",
	"routing.http.response.x_frame_options.header_value",
}

_pf_elb_lsattr_for := {
	"application": _pf_elb_lsattr_alb,
	"network": {"tcp.idle_timeout.seconds"},
	"gateway": {"tcp.idle_timeout.seconds", "send_tcp_reset.on_idle_timeout.enabled"},
}

_pf_elb_lsattr_known := (_pf_elb_lsattr_for.application | _pf_elb_lsattr_for.network) | _pf_elb_lsattr_for.gateway

_pf_elb_rules := resources_of_type("AWS::ElasticLoadBalancingV2::ListenerRule")

# The *Config that belongs to each RuleCondition.Field.
_pf_elb_cond_config := {
	"host-header": "HostHeaderConfig",
	"path-pattern": "PathPatternConfig",
	"http-header": "HttpHeaderConfig",
	"http-request-method": "HttpRequestMethodConfig",
	"query-string": "QueryStringConfig",
	"source-ip": "SourceIpConfig",
}

_pf_elb_conditions(rule) := flatten_list(rule, "Properties.Conditions")

_pf_elb_cond_cfg(cond) := c if {
	f := object.get(cond, "Field", "")
	c := object.get(cond, object.get(_pf_elb_cond_config, f, ""), {})
	is_object(c)
}

# Values / RegexValues can sit on the condition itself or inside its *Config.
_pf_elb_cond_list(o, key) := l if {
	l := object.get(o, key, [])
	is_array(l)
}

_pf_elb_cond_of(cond, key) := array.concat(
	_pf_elb_cond_list(cond, key),
	_pf_elb_cond_list(_pf_elb_cond_cfg(cond), key),
)

_pf_elb_cond_values(cond) := array.concat(_pf_elb_cond_of(cond, "Values"), _pf_elb_cond_of(cond, "RegexValues"))

# The target groups one action forwards to, from either shape.
_pf_elb_action_tgs(a) := {g |
	some tg in array.concat([{"TargetGroupArn": object.get(a, "TargetGroupArn", null)}], _pf_elb_fwd_tgs(a))
	g := _pf_elb_tuple_tg(tg)
}

# Every (listener, target group) pair this template wires up.
_pf_elb_listener_tgs contains {"listener": l, "tg": g} if {
	some a in _pf_elb_all_actions
	l := _pf_elb_action_listener(a.name)
	some g in _pf_elb_action_tgs(a.value)
}

# The target group protocols each listener protocol accepts. QUIC is left out
# on purpose: the docs only pin down TCP_QUIC.
_pf_elb_lproto_tgproto := {
	"HTTP": {"HTTP", "HTTPS"},
	"HTTPS": {"HTTP", "HTTPS"},
	"TCP": {"TCP", "TLS", "TCP_UDP"},
	"TLS": {"TCP", "TLS", "TCP_UDP"},
	"UDP": {"UDP", "TCP_UDP"},
	"TCP_UDP": {"TCP_UDP"},
	"TCP_QUIC": {"TCP_QUIC"},
	"GENEVE": {"GENEVE"},
}

# The VPC of a load balancer, when its subnets are resources of this template.
_pf_elb_lb_vpc(lb) := v if {
	vpcs := {x |
		some s in flatten_list(lb, "Properties.Subnets")
		sub := _pf_elb_ref(s.value)
		x := resolve(sub, "Properties.VpcId")
	}
	count(vpcs) == 1
	some v in vpcs
}
