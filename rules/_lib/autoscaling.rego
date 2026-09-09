package cdk_preflight

import rego.v1

_pf_aslib_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

# プロパティ不在の証明（AGENTS.md の sanctioned exception）
_pf_aslib_absent(name, key) if object.get(_pf_aslib_props(name), key, "__pf_absent") == "__pf_absent"

# ネストしたキーの不在判定。path は上位から順のキー列。
_pf_aslib_absent_at(name, path) if {
	obj := object.get(_pf_aslib_props(name), array.slice(path, 0, count(path) - 1), {})
	is_object(obj)
	object.get(obj, path[count(path) - 1], "__pf_absent") == "__pf_absent"
}

# 生プロパティ（オブジェクト内の値をそのまま読む。intrinsic はマーカーオブジェクトのまま）
_pf_aslib_raw(name, path) := v if {
	v := object.get(_pf_aslib_props(name), path, "__pf_absent")
	v != "__pf_absent"
}

# 配列。flatten_list と違い不在は undefined（不在と空配列を区別できる）
_pf_aslib_arr(name, path) := a if {
	a := _pf_aslib_raw(name, path)
	is_array(a)
}

_pf_aslib_obj(name, path) := o if {
	o := _pf_aslib_raw(name, path)
	is_object(o)
	not o["__kind"]
	not o["__dynamic"]
}

# ユーザーが書いたリテラル文字列。Ref/GetAtt はテンプレート内の論理 ID に解決されるので除く。
_pf_aslib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# 数値。to_number は非数値で undefined なので Ref/トークンは自然に落ちる。
_pf_aslib_num(name, path) := n if {
	v := resolve(name, path)
	v != null
	not is_boolean(v)
	n := to_number(v)
}

# ScalingPolicy の実効 PolicyType（未指定時の既定は SimpleScaling）
_pf_aslib_ptype(name) := t if {
	t := resolve(name, "Properties.PolicyType")
	is_string(t)
}

_pf_aslib_ptype(name) := "SimpleScaling" if _pf_aslib_absent(name, "PolicyType")

# 子リソース（ScalingPolicy / ScheduledAction / LifecycleHook / WarmPool）から
# 同一テンプレート内の AutoScalingGroup 論理 ID へ
_pf_aslib_group(name) := g if {
	g := resolve(name, "Properties.AutoScalingGroupName")
	g in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
}

# AutoScalingGroup から同一テンプレート内の LaunchTemplate 論理 ID へ（単体・MixedInstancesPolicy 両方）
_pf_aslib_lt(asg) := lt if {
	lt := resolve(asg, "Properties.LaunchTemplate.LaunchTemplateId")
	lt in resources_of_type("AWS::EC2::LaunchTemplate")
}

_pf_aslib_lt(asg) := lt if {
	lt := resolve(asg, "Properties.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.LaunchTemplateId")
	lt in resources_of_type("AWS::EC2::LaunchTemplate")
}

_pf_aslib_overrides(name) := _pf_aslib_arr(name, ["MixedInstancesPolicy", "LaunchTemplate", "Overrides"])

# ARN のセグメント（region は 3、account は 4、service は 2）
_pf_aslib_arn(v) := parts if {
	_pf_aslib_lit(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
}

_pf_aslib_arn_service(v) := _pf_aslib_arn(v)[2]

_pf_aslib_arn_region(v) := r if {
	r := _pf_aslib_arn(v)[3]
	r != ""
}

# LifecycleHook の通知先が Lambda 関数か（リテラル ARN / テンプレート内リソースの両方）
_pf_aslib_target_lambda(name) if _pf_aslib_arn_service(resolve(name, "Properties.NotificationTargetARN")) == "lambda"

_pf_aslib_target_lambda(name) if {
	t := resolve(name, "Properties.NotificationTargetARN")
	t in resources_of_type("AWS::Lambda::Function")
}

# Recurrence（裸の 5 フィールド Unix cron）をフィールドに分解する
_pf_aslib_cron_fields(s) := f if {
	_pf_aslib_lit(s)
	f := [x | some x in split(s, " "); x != ""]
}

# 数字トークン。to_number("03") は engine のビルドでは undefined なので先頭ゼロを落とす。
_pf_aslib_int(s) := 0 if regex.match("^0+$", s)

_pf_aslib_int(s) := n if {
	regex.match("^[0-9]+$", s)
	t := trim_left(s, "0")
	t != ""
	n := to_number(t)
}

# 1 フィールド内の裸の数値。範囲(a-b)・リスト(a,b)・ステップ(*/n)を分解した後の数字だけを見る。
# 月名・曜日名・ワイルドカードは数値にならないので自然に無視される（誤検知を出さないための割り切り）。
_pf_aslib_cron_nums(field) := [n |
	some part in split(field, ",")
	some seg in split(split(part, "/")[0], "-")
	n := _pf_aslib_int(seg)
]

_pf_aslib_steps(name) := _pf_aslib_arr(name, ["StepAdjustments"])

# StepAdjustment の境界。未指定は ±センチネル。Ref などのマーカーは undefined のまま返し、
# その step を含む判定を丸ごと黙らせる（誤検知を出さないため）。
_pf_aslib_step_lo(s) := n if {
	v := object.get(s, "MetricIntervalLowerBound", null)
	v != null
	not is_object(v)
	n := to_number(v)
}

_pf_aslib_step_lo(s) := -1000000000 if object.get(s, "MetricIntervalLowerBound", null) == null

_pf_aslib_step_hi(s) := n if {
	v := object.get(s, "MetricIntervalUpperBound", null)
	v != null
	not is_object(v)
	n := to_number(v)
}

_pf_aslib_step_hi(s) := 1000000000 if object.get(s, "MetricIntervalUpperBound", null) == null

_pf_aslib_step_ivals(name) := [[lo, hi] |
	some s in _pf_aslib_steps(name)
	is_object(s)
	lo := _pf_aslib_step_lo(s)
	hi := _pf_aslib_step_hi(s)
]

_pf_aslib_step_nulls(name, key) := count([1 |
	some s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, key, null) == null
])

_pf_aslib_step_bothnull(name) if {
	some s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, "MetricIntervalLowerBound", null) == null
	object.get(s, "MetricIntervalUpperBound", null) == null
}

# 区間の重なり/隙間を見る前提条件。サービス側もこの順で検証するので、
# null 境界の違反があるうちは重なり判定を出さない（ルール同士が二重に鳴らないように）。
_pf_aslib_step_wellformed(name) if {
	_pf_aslib_step_nulls(name, "MetricIntervalLowerBound") <= 1
	_pf_aslib_step_nulls(name, "MetricIntervalUpperBound") <= 1
	not _pf_aslib_step_bothnull(name)
	count(_pf_aslib_step_ivals(name)) == count(_pf_aslib_steps(name))
}

_pf_aslib_pmetrics(name) := _pf_aslib_arr(name, ["PredictiveScalingConfiguration", "MetricSpecifications"])

_pf_aslib_pcustom := ["CustomizedLoadMetricSpecification", "CustomizedScalingMetricSpecification", "CustomizedCapacityMetricSpecification"]

_pf_aslib_hooks(name) := _pf_aslib_arr(name, ["LifecycleHookSpecificationList"])

_pf_aslib_tags(name) := _pf_aslib_arr(name, ["Tags"])
