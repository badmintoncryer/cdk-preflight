package cdk_preflight

import rego.v1

# Elastic Beanstalk: OptionSettings のテーブル駆動検査で使う共通部品（診断は出さない）。
#
# 検証は「指定した値 + スタックの既定値」を合成した状態に対してかかるので、
# 片側だけの指定でも鳴る（MinSize=6 だけ、RollingUpdateEnabled=true と
# MinInstancesInService だけ、など）。制約の出典と実測は ~/cdk-preflight-surveys/elasticbeanstalk-314/。
#
# OptionSettings の各要素は「Namespace / OptionName / Value がすべてリテラル」で、
# Fn::If の分岐になっていないものだけを _pf_eblib_opt に載せる。Ref / Sub / GetAtt
# （マーカーオブジェクト）や `{{resolve:...}}` を含む値は載らないので、実 CDK テンプレートでは黙る。
# 表のキーは "<正規化した namespace>|<OptionName>"。正規化は
#   aws:elb:listener:<port> -> aws:elb:listener
#   aws:elb:policies:<name> -> aws:elb:policies
#   aws:elasticbeanstalk:environment:process:<name> -> aws:elasticbeanstalk:environment:process

_pf_eblib_inf := 1000000000000

_pf_eblib_ninf := -1000000000000

_pf_eblib_props(rn) := p if {
	p := input.resources[rn].properties
	is_object(p)
}

_pf_eblib_res contains rn if {
	some rn in resources_of_type("AWS::ElasticBeanstalk::ConfigurationTemplate")
}

_pf_eblib_res contains rn if {
	some rn in resources_of_type("AWS::ElasticBeanstalk::Environment")
}

# Value を文字列にする（テンプレートでは数値・真偽値で書かれることもある）。本体が互いに素なので多重出力にならない。
_pf_eblib_valstr(v) := v if is_string(v)

_pf_eblib_valstr(v) := sprintf("%v", [v]) if is_number(v)

_pf_eblib_valstr(v) := "true" if v == true

_pf_eblib_valstr(v) := "false" if v == false

# 3 つとも文字列リテラル、Fn::If の分岐ではなく、値に動的参照が混ざらない要素
_pf_eblib_lit_opt(it) if {
	is_object(it)
	is_string(it.Namespace)
	is_string(it.OptionName)
	not _pf_ll_conditional(it)
	s := _pf_eblib_valstr(it.Value)
	not contains(s, "{{")
}

_pf_eblib_nsn(ns) := n if {
	a := regex.replace(ns, `^aws:elb:listener:[0-9]+$`, "aws:elb:listener")
	b := regex.replace(a, `^aws:elb:policies:.+$`, "aws:elb:policies")
	n := regex.replace(b, `^aws:elasticbeanstalk:environment:process:.+$`, "aws:elasticbeanstalk:environment:process")
}

_pf_eblib_opt contains {"rn": rn, "i": i, "ns": ns, "nm": nm, "s": s, "k": k} if {
	some rn in _pf_eblib_res
	arr := object.get(_pf_eblib_props(rn), "OptionSettings", null)
	is_array(arr)
	some i, it in arr
	_pf_eblib_lit_opt(it)
	ns := it.Namespace
	nm := it.OptionName
	s := _pf_eblib_valstr(it.Value)
	k := sprintf("%s|%s", [_pf_eblib_nsn(ns), nm])
}

# リソース rn の中でオプション k に書かれた値の一覧（生の並び順）
_pf_eblib_vals(rn, k) := [o.s |
	o := _pf_eblib_opt[_]
	o.rn == rn
	o.k == k
]

_pf_eblib_on(rn, k) if {
	vs := _pf_eblib_vals(rn, k)
	count(vs) == 1
	lower(vs[0]) == "true"
}

# 「オプションの不在」を根拠にする推論（既定値との合成）の前提: OptionSettings の要素がすべてリテラル
_pf_eblib_clean(rn) if {
	arr := object.get(_pf_eblib_props(rn), "OptionSettings", [])
	is_array(arr)
	count([1 |
		some it in arr
		not _pf_eblib_lit_opt(it)
	]) == 0
}

# 別テンプレート / 別環境の設定を取り込まない（取り込むと不在の推論が成り立たない）
_pf_eblib_standalone(rn) if {
	p := _pf_eblib_props(rn)
	object.get(p, "TemplateName", "__pf_absent") == "__pf_absent"
	object.get(p, "SourceConfiguration", "__pf_absent") == "__pf_absent"
}

# AWS 提供のプラットフォーム（ARN のアカウント部が空）か、PlatformArn / SolutionStackName のどちらか。
# カスタムプラットフォームは独自の名前空間を持てるので、名前空間の検査から外す。
_pf_eblib_std_platform(rn) if {
	object.get(_pf_eblib_props(rn), "PlatformArn", "__pf_absent") == "__pf_absent"
}

_pf_eblib_std_platform(rn) if {
	arn := object.get(_pf_eblib_props(rn), "PlatformArn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[4] == ""
}

# リテラルのオブジェクト（Ref / GetAtt / Sub / Fn::If のマーカーではない）
_pf_eblib_lit_obj(o) if {
	is_object(o)
	object.get(o, "__kind", "_") == "_"
	object.get(o, "__dynamic", "_") == "_"
	object.get(o, "__conditional", "_") == "_"
}

_pf_eblib_num(s) := to_number(s) if regex.match(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`, s)

# 数値そのもの、または数値の文字列（プロパティが integer 型のとき、どちらの書き方もある）
_pf_eblib_numv(v) := v if is_number(v)

_pf_eblib_numv(v) := _pf_eblib_num(v) if is_string(v)

_pf_eblib_side(n, rg) := "below" if n < rg[0]

_pf_eblib_side(n, rg) := "above" if n > rg[1]

_pf_eblib_rtext(rg) := sprintf("%v to %v", [rg[0], rg[1]]) if {
	rg[0] > _pf_eblib_ninf
	rg[1] < _pf_eblib_inf
}

_pf_eblib_rtext(rg) := sprintf("at least %v", [rg[0]]) if rg[1] >= _pf_eblib_inf

_pf_eblib_rtext(rg) := sprintf("at most %v", [rg[1]]) if rg[0] <= _pf_eblib_ninf

_pf_eblib_isbool(s) if lower(s) == "true"

_pf_eblib_isbool(s) if lower(s) == "false"

_pf_eblib_enum_ok(o, list) if {
	not _pf_eblib_enum_cs[o.k]
	lower(o.s) == lower(list[_])
}

_pf_eblib_enum_ok(o, list) if {
	_pf_eblib_enum_cs[o.k]
	o.s == list[_]
}

_pf_eblib_rx_ok(o, rx) if {
	not _pf_eblib_rx_ci[o.k]
	regex.match(rx, o.s)
}

_pf_eblib_rx_ok(o, rx) if {
	_pf_eblib_rx_ci[o.k]
	regex.match(rx, lower(o.s))
}

_pf_eblib_ret_ok(n) if _pf_eblib_retention[_] == n

_pf_eblib_ns_ok(ns) if lower(ns) in _pf_eblib_ns_known

_pf_eblib_ns_ok(ns) if startswith(lower(ns), _pf_eblib_ns_prefix[_])

# コマンドの BatchSize の上限は BatchSizeType で変わる（Percentage は 100、Fixed は 10000）。
# 型が未指定のときの既定は Percentage だが、API の実測が「10000 は HIGH」というだけなので、未指定側は 10000 まで通す。
_pf_eblib_batch_type(rn) := t if {
	vs := _pf_eblib_vals(rn, "aws:elasticbeanstalk:command|BatchSizeType")
	count(vs) == 1
	t := lower(vs[0])
}

_pf_eblib_batch_hi(rn) := 100 if _pf_eblib_batch_type(rn) == "percentage"

_pf_eblib_batch_hi(rn) := 10000 if {
	t := _pf_eblib_batch_type(rn)
	t != "percentage"
}

_pf_eblib_batch_hi(rn) := 10000 if {
	count(_pf_eblib_vals(rn, "aws:elasticbeanstalk:command|BatchSizeType")) == 0
	_pf_eblib_clean(rn)
}

# Spot: SpotFleetOnDemandBase は MaxSize（未指定なら既定の 4）を超えられない。EnableSpot=true のときだけ。
_pf_eblib_maxsize(rn) := n if {
	vs := _pf_eblib_vals(rn, "aws:autoscaling:asg|MaxSize")
	count(vs) == 1
	n := _pf_eblib_num(vs[0])
}

_pf_eblib_maxsize(rn) := 4 if {
	count(_pf_eblib_vals(rn, "aws:autoscaling:asg|MaxSize")) == 0
	_pf_eblib_clean(rn)
	_pf_eblib_standalone(rn)
}

# ISO 8601 の期間（PT<h>H<m>M<s>S だけを見る。ほかの書き方には黙る）
_pf_eblib_iso_ok(s) if {
	s != "PT"
	regex.match(`^PT([0-9]+H)?([0-9]+M)?([0-9]+S)?$`, s)
}

_pf_eblib_iso_part(s, unit) := n if {
	m := regex.find_n(sprintf("[0-9]+%s", [unit]), s, 1)
	count(m) == 1
	n := to_number(substring(m[0], 0, count(m[0]) - 1))
}

_pf_eblib_iso_part(s, unit) := 0 if {
	count(regex.find_n(sprintf("[0-9]+%s", [unit]), s, 1)) == 0
}

_pf_eblib_iso_secs(s) := 3600 * _pf_eblib_iso_part(s, "H") + 60 * _pf_eblib_iso_part(s, "M") + _pf_eblib_iso_part(s, "S") if _pf_eblib_iso_ok(s)

_pf_eblib_cron_fields(s) := count(regex.find_n(`[^ \t]+`, s, -1))

_pf_eblib_types(s) := [x |
	some t in split(s, ",")
	x := trim_space(t)
	x != ""
]

# ライフサイクルのルール名 -> 保持数のプロパティ名
_pf_eblib_lc_field := {"MaxAgeRule": "MaxAgeInDays", "MaxCountRule": "MaxCount"}

_pf_eblib_lc_has_rule(vc) if {
	_pf_eblib_lc_field[rk]
	r := object.get(vc, rk, null)
	_pf_eblib_lit_obj(r)
}

_pf_eblib_lc_enabled(r) if r.Enabled == true

_pf_eblib_lc_enabled(r) if r.Enabled == "true"

# Timeout（PT5M〜PT1H）と PauseTime（〜PT1H）の秒数の限界
_pf_eblib_dur_timeout_lo := 300

_pf_eblib_dur_max := 3600


_pf_eblib_r_asg := {
	"aws:autoscaling:asg|Cooldown": [0, 10000],
	"aws:autoscaling:asg|MinSize": [0, 10000],
	"aws:autoscaling:asg|MaxSize": [0, 10000],
}

_pf_eblib_r_deploy := {
	"aws:elasticbeanstalk:command|Timeout": [1, 3600],
	"aws:autoscaling:updatepolicy:rollingupdate|MaxBatchSize": [1, 10000],
	"aws:autoscaling:updatepolicy:rollingupdate|MinInstancesInService": [0, 9999],
	"aws:elasticbeanstalk:control|LaunchTimeout": [0, _pf_eblib_inf],
}

_pf_eblib_r_elb := {
	"aws:elb:healthcheck|HealthyThreshold": [2, 10],
	"aws:elb:healthcheck|Interval": [5, 300],
	"aws:elb:healthcheck|Timeout": [2, 60],
	"aws:elb:healthcheck|UnhealthyThreshold": [2, 10],
	"aws:elb:listener|InstancePort": [1, 65535],
	"aws:elb:policies|ConnectionSettingIdleTimeout": [1, 3600],
	"aws:elb:policies|ConnectionDrainingTimeout": [1, 3600],
	"aws:elb:policies|Stickiness Cookie Expiration": [0, 1000000],
}

_pf_eblib_r_process := {
	"aws:elasticbeanstalk:environment:process|Port": [1, 65535],
	"aws:elasticbeanstalk:environment:process|HealthCheckTimeout": [_pf_eblib_ninf, 60],
}

_pf_eblib_r_trigger := {
	"aws:autoscaling:trigger|Period": [1, 600],
	"aws:autoscaling:trigger|EvaluationPeriods": [1, _pf_eblib_inf],
	"aws:autoscaling:trigger|LowerThreshold": [0, _pf_eblib_inf],
	"aws:autoscaling:trigger|UpperThreshold": [0, _pf_eblib_inf],
}

_pf_eblib_r_spot := {
	"aws:ec2:instances|SpotMaxPrice": [0.001, 20],
	"aws:ec2:instances|SpotFleetOnDemandAboveBasePercentage": [0, 100],
	"aws:ec2:instances|SpotFleetOnDemandBase": [0, _pf_eblib_inf],
}

_pf_eblib_r_throughput := {
	"aws:autoscaling:launchconfiguration|RootVolumeThroughput": [125, 1000],
}

_pf_eblib_bool := {
	"aws:autoscaling:asg|EnableCapacityRebalancing",
	"aws:autoscaling:launchconfiguration|DisableIMDSv1",
	"aws:autoscaling:launchconfiguration|DisableDefaultEC2SecurityGroup",
	"aws:autoscaling:launchconfiguration|LaunchTemplateTagPropagationEnabled",
	"aws:autoscaling:updatepolicy:rollingupdate|RollingUpdateEnabled",
	"aws:ec2:vpc|AssociatePublicIpAddress",
	"aws:elasticbeanstalk:cloudwatch:logs|DeleteOnTerminate",
	"aws:elasticbeanstalk:cloudwatch:logs|StreamLogs",
	"aws:elasticbeanstalk:cloudwatch:logs:health|DeleteOnTerminate",
	"aws:elasticbeanstalk:cloudwatch:logs:health|HealthStreamingEnabled",
	"aws:elasticbeanstalk:command|IgnoreHealthCheck",
	"aws:elasticbeanstalk:control|RollbackLaunchOnFailure",
	"aws:elasticbeanstalk:healthreporting:system|EnhancedHealthAuthEnabled",
	"aws:elasticbeanstalk:managedactions:platformupdate|InstanceRefreshEnabled",
	"aws:elasticbeanstalk:managedactions|ManagedActionsEnabled",
	"aws:elasticbeanstalk:monitoring|Automatically Terminate Unhealthy Instances",
	"aws:elasticbeanstalk:hostmanager|LogPublicationControl",
	"aws:elb:listener|ListenerEnabled",
	"aws:elb:loadbalancer|CrossZone",
	"aws:elb:policies|ConnectionDrainingEnabled",
	"aws:elb:policies|Stickiness Policy",
	"aws:autoscaling:scheduledaction|Suspend",
	"aws:rds:dbinstance|HasCoupledDatabase",
}

_pf_eblib_enum := {
	"aws:autoscaling:trigger|MeasureName": ["CPUUtilization", "NetworkIn", "NetworkOut", "DiskWriteOps", "DiskReadBytes", "DiskReadOps", "DiskWriteBytes", "Latency", "RequestCount", "HealthyHostCount", "UnHealthyHostCount"],
	"aws:autoscaling:trigger|Unit": ["Seconds", "Percent", "Bytes", "Bits", "Count", "Bytes/Second", "Bits/Second", "Count/Second", "None"],
	"aws:autoscaling:trigger|Statistic": ["Minimum", "Maximum", "Sum", "Average"],
	"aws:ec2:instances|SpotAllocationStrategy": ["capacity-optimized", "lowest-price", "capacity-optimized-prioritized", "price-capacity-optimized"],
	"aws:elasticbeanstalk:command|BatchSizeType": ["Percentage", "Fixed"],
	"aws:elasticbeanstalk:command|DeploymentPolicy": ["AllAtOnce", "Rolling", "RollingWithAdditionalBatch", "Immutable", "TrafficSplitting"],
	"aws:elasticbeanstalk:control|LaunchType": ["Migration", "Normal"],
	"aws:elasticbeanstalk:environment|EnvironmentType": ["LoadBalanced", "SingleInstance"],
	"aws:elasticbeanstalk:environment|LoadBalancerType": ["classic", "application", "network"],
	"aws:elasticbeanstalk:environment:proxy|ProxyServer": ["apache", "nginx", "none"],
	"aws:autoscaling:updatepolicy:rollingupdate|RollingUpdateType": ["Time", "Health", "Immutable"],
	"aws:elasticbeanstalk:healthreporting:system|HealthCheckSuccessThreshold": ["Ok", "Warning", "Degraded", "Severe"],
	"aws:elasticbeanstalk:healthreporting:system|SystemType": ["basic", "enhanced"],
	"aws:elasticbeanstalk:managedactions:platformupdate|UpdateLevel": ["patch", "minor"],
	"aws:elasticbeanstalk:sns:topics|Notification Protocol": ["http", "https", "email", "email-json", "sqs"],
	"aws:elasticbeanstalk:xray|XRayEnabled": ["true", "false"],
	"aws:elb:loadbalancer|LoadBalancerSSLPortProtocol": ["HTTPS", "SSL"],
	"aws:autoscaling:launchconfiguration|RootVolumeType": ["standard", "gp2", "gp3", "io1"],
	"aws:elb:listener|InstanceProtocol": ["HTTP", "TCP", "HTTPS", "SSL"],
	"aws:elb:listener|ListenerProtocol": ["HTTP", "TCP", "HTTPS", "SSL"],
}

_pf_eblib_enum_cs := {
	"aws:autoscaling:launchconfiguration|RootVolumeType",
	"aws:elb:listener|InstanceProtocol",
	"aws:elb:listener|ListenerProtocol",
}

_pf_eblib_rx := {
	"aws:autoscaling:launchconfiguration|ImageId": `^ami-[a-z0-9]+$`,
	"aws:autoscaling:launchconfiguration|SSHSourceRestriction": `^.+,\d+,\d+,.+$`,
	"aws:elasticbeanstalk:application|Application Healthcheck URL": `^((HTTP|TCP|SSL|HTTPS):)?(\d*)(/.*)?$`,
	"aws:elb:healthcheck|Target": `^((HTTP|TCP|SSL|HTTPS):)?(\d*)(/.*)?$`,
	"aws:elasticbeanstalk:application:environment|JDBC_CONNECTION_STRING": `^\S*$`,
	"aws:elasticbeanstalk:managedactions|PreferredStartTime": `^(sun|mon|tue|wed|thu|fri|sat):([01][0-9]|2[0-3]):[0-5][0-9]$`,
}

_pf_eblib_rx_ci := {
	"aws:elasticbeanstalk:managedactions|PreferredStartTime",
}

_pf_eblib_retention := [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]

_pf_eblib_ns_known := {
	"aws:autoscaling:asg",
	"aws:autoscaling:launchconfiguration",
	"aws:autoscaling:scheduledaction",
	"aws:autoscaling:trigger",
	"aws:autoscaling:updatepolicy:rollingupdate",
	"aws:cloudformation:template:parameter",
	"aws:ec2:instances",
	"aws:ec2:vpc",
	"aws:elasticbeanstalk:application",
	"aws:elasticbeanstalk:application:environment",
	"aws:elasticbeanstalk:command",
	"aws:elasticbeanstalk:control",
	"aws:elasticbeanstalk:environment",
	"aws:elasticbeanstalk:healthreporting:system",
	"aws:elasticbeanstalk:hostmanager",
	"aws:elasticbeanstalk:managedactions",
	"aws:elasticbeanstalk:monitoring",
	"aws:elasticbeanstalk:sns:topics",
	"aws:elasticbeanstalk:xray",
	"aws:elasticbeanstalk:windows:activedirectory",
	"aws:elasticbeanstalk:customoption",
	"aws:elasticbeanstalk:sqsd",
	"aws:elasticbeanstalk:trafficsplitting",
	"aws:elb:healthcheck",
	"aws:elb:listener",
	"aws:elb:loadbalancer",
	"aws:elb:policies",
	"aws:rds:dbinstance",
}

_pf_eblib_ns_prefix := [
	"aws:elasticbeanstalk:container:",
	"aws:elasticbeanstalk:environment:",
	"aws:elasticbeanstalk:cloudwatch:",
	"aws:elasticbeanstalk:managedactions:",
	"aws:elasticbeanstalk:application:environmentsecrets",
	"aws:elasticbeanstalk:eks",
	"aws:elasticbeanstalk:cluster",
	"aws:elb:listener:",
	"aws:elb:policies:",
	"aws:elbv2:",
]
