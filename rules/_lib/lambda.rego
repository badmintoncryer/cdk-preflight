package cdk_preflight

import rego.v1

# Shared helpers for the AWS::Lambda::EventSourceMapping rules: literal-vs-token
# discrimination, ARN segments, raw-document access (resolve() cannot prove a key
# absent) and — the one every rule needs — which event source a mapping points at.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_lam_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# ARN segments of a literal ARN; undefined for intrinsics and non-ARN strings.
_pf_lam_arn(v) := parts if {
	_pf_lam_lit(v)
	parts := split(v, ":")
	count(parts) >= 6
	parts[0] == "arn"
}

# Raw properties. The preprocessed document is the only place where "the key is
# absent" can be told apart from "the value is a token".
_pf_lam_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_lam_has(name, k) if {
	object.get(_pf_lam_props(name), k, "__pf_absent") != "__pf_absent"
}

_pf_lam_get(name, k) := v if {
	v := object.get(_pf_lam_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_lam_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

_pf_lam_esm := resources_of_type("AWS::Lambda::EventSourceMapping")

# --- which event source does this mapping read from? ------------------------
# The config blocks are decisive: they exist only for one source family each.

_pf_lam_is(name, "docdb") if _pf_lam_has(name, "DocumentDBEventSourceConfig")

_pf_lam_is(name, "selfkafka") if _pf_lam_has(name, "SelfManagedEventSource")

_pf_lam_is(name, "kafka") if _pf_lam_has(name, "AmazonManagedKafkaEventSourceConfig")

# An in-template source resource: resolve() hands back the logical id.
_pf_lam_src_type := {
	"AWS::SQS::Queue": "sqs",
	"AWS::Kinesis::Stream": "kinesis",
	"AWS::DynamoDB::Table": "dynamodb",
	"AWS::DynamoDB::GlobalTable": "dynamodb",
	"AWS::MSK::Cluster": "kafka",
	"AWS::MSK::ServerlessCluster": "kafka",
	"AWS::AmazonMQ::Broker": "mq",
	"AWS::DocDB::DBCluster": "docdb",
}

_pf_lam_srcarn(name, kind) if {
	src := resolve(name, "Properties.EventSourceArn")
	some t, k in _pf_lam_src_type
	src in resources_of_type(t)
	k == kind
}

# A literal ARN: the service segment names the source. DocumentDB clusters carry
# an rds ARN, so they are only recognised through DocumentDBEventSourceConfig.
_pf_lam_arn_kind := {
	"sqs": "sqs",
	"kinesis": "kinesis",
	"dynamodb": "dynamodb",
	"kafka": "kafka",
	"mq": "mq",
}

_pf_lam_srcarn(name, kind) if {
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	_pf_lam_arn_kind[parts[2]] == kind
}

# The union: what the mapping reads from, by config block or by source ARN.
_pf_lam_is(name, kind) if _pf_lam_srcarn(name, kind)

# The source ARN names something other than `kind`. Unlike _pf_lam_not this
# ignores the config blocks, so a rule can say "this block is on the wrong ARN".
_pf_lam_arn_not(name, kind) if {
	some other in {"sqs", "kinesis", "dynamodb", "kafka", "mq", "docdb"}
	other != kind
	_pf_lam_srcarn(name, other)
}

# Stream sources: the family that accepts StartingPosition, offsets and shard state.
_pf_lam_stream(name) if _pf_lam_is(name, "kinesis")

_pf_lam_stream(name) if _pf_lam_is(name, "dynamodb")

_pf_lam_stream(name) if _pf_lam_is(name, "kafka")

_pf_lam_stream(name) if _pf_lam_is(name, "selfkafka")

# The mapping's source is known to be something other than `kind`.
_pf_lam_not(name, kind) if {
	some other in {"sqs", "kinesis", "dynamodb", "kafka", "selfkafka", "mq", "docdb"}
	other != kind
	_pf_lam_is(name, other)
}

# --- event filter patterns --------------------------------------------------
# Filters[].Pattern is a JSON *string* holding an EventBridge pattern. There is
# no walk builtin and Rego forbids recursion, so the traversal is unrolled to
# four object levels: DynamoDB patterns are the deepest in practice
# (dynamodb.NewImage.<attribute>.<type>).
# ponytail: depth-capped at 4, deepen only if a real pattern nests further.

_pf_lam_filters(name) := f if {
	f := object.get(_pf_lam_obj(_pf_lam_props(name), "FilterCriteria"), "Filters", [])
	is_array(f)
}

_pf_lam_pat(f) := o if {
	is_object(f)
	p := object.get(f, "Pattern", "")
	is_string(p)
	o := json.unmarshal(p)
	is_object(o)
}

_pf_lam_scalar(v) if {
	not is_object(v)
	not is_array(v)
}

# [path, value] for every scalar sitting where the pattern grammar wants an array.
_pf_lam_pat_scalars(o) := array.concat(
	array.concat(
		[[[k], v] | some k, v in o; _pf_lam_scalar(v)],
		[[[k1, k2], v] | some k1, o1 in o; is_object(o1); some k2, v in o1; _pf_lam_scalar(v)],
	),
	array.concat(
		[[[k1, k2, k3], v] | some k1, o1 in o; is_object(o1); some k2, o2 in o1; is_object(o2); some k3, v in o2; _pf_lam_scalar(v)],
		[[[k1, k2, k3, k4], v] | some k1, o1 in o; is_object(o1); some k2, o2 in o1; is_object(o2); some k3, o3 in o2; is_object(o3); some k4, v in o3; _pf_lam_scalar(v)],
	),
)

# Objects nested inside a match array: these are the operator objects
# ({"prefix": "a"}, {"numeric": [">", 1]}, ...).
_pf_lam_pat_ops(o) := array.concat(
	array.concat(
		[[[k], x] | some k, a in o; is_array(a); some x in a; is_object(x)],
		[[[k1, k2], x] | some k1, o1 in o; is_object(o1); some k2, a in o1; is_array(a); some x in a; is_object(x)],
	),
	array.concat(
		[[[k1, k2, k3], x] | some k1, o1 in o; is_object(o1); some k2, o2 in o1; is_object(o2); some k3, a in o2; is_array(a); some x in a; is_object(x)],
		[[[k1, k2, k3, k4], x] | some k1, o1 in o; is_object(o1); some k2, o2 in o1; is_object(o2); some k3, o3 in o2; is_object(o3); some k4, a in o3; is_array(a); some x in a; is_object(x)],
	),
)

_pf_lam_has_key(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

# A property that CloudFormation accepts as either a scalar or a list.
_pf_lam_list(v) := v if is_array(v)

_pf_lam_list(v) := [v] if is_string(v)

_pf_lam_ppc(name) := c if c := _pf_lam_obj(_pf_lam_props(name), "ProvisionedPollerConfig")
# --- #75 非 ESM 分で足す共有ヘルパー -----------------------------------------
# rules/_lib/lambda.rego の末尾に足す。#117 がマージされてワークツリーが
# main に戻ってから適用する。

_pf_lam_alias := resources_of_type("AWS::Lambda::Alias")

_pf_lam_ver := resources_of_type("AWS::Lambda::Version")

_pf_lam_fn := resources_of_type("AWS::Lambda::Function")

_pf_lam_perm := resources_of_type("AWS::Lambda::Permission")

_pf_lam_url := resources_of_type("AWS::Lambda::Url")

_pf_lam_layer := resources_of_type("AWS::Lambda::LayerVersion")

_pf_lam_layerperm := resources_of_type("AWS::Lambda::LayerVersionPermission")

_pf_lam_csc := resources_of_type("AWS::Lambda::CodeSigningConfig")

_pf_lam_eic := resources_of_type("AWS::Lambda::EventInvokeConfig")

# EventInvokeConfig の宛先。OnSuccess と OnFailure は制約がほぼ共通なので
# 1 つの集合にまとめ、どちら側かを second element に残す。
_pf_lam_eic_dest contains [name, side, dest] if {
	some name in _pf_lam_eic
	some side in ["OnSuccess", "OnFailure"]
	dest := resolve(name, sprintf("Properties.DestinationConfig.%v.Destination", [side]))
	is_string(dest)
}

# 署名プロファイルのバージョン ARN。CodeSigningConfig の唯一の必須要素で、
# 4 本のルールが同じリストを回すのでここに置く。
_pf_lam_csc_profiles contains [name, arn] if {
	some name in _pf_lam_csc
	pubs := _pf_lam_obj(_pf_lam_props(name), "AllowedPublishers")
	some arn in _pf_lam_list(object.get(pubs, "SigningProfileVersionArns", []))
	is_string(arn)
}

# --- #75 Function 系で足す共有ヘルパー ---------------------------------------

# テンプレート内の別リソースの生プロパティ。Properties を持たないリソース
# （AWS::EFS::FileSystem など）でも undefined にならないようにする。
_pf_lam_res_props(id) := p if {
	p := object.get(object.get(input.resources, id, {}), "properties", {})
	is_object(p)
}

# テンプレート内のリソースを指す組み込み関数の論理 ID。前処理済みドキュメントでは
# Ref も GetAtt も {"__kind": "resource" | "getatt:Arn", "__ref": "<論理ID>"} に
# マーカー化されているので、生の {"Ref": ...} を探しても見つからない（2026-09-07 実測）。
_pf_lam_ref(v) := id if {
	is_object(v)
	id := object.get(v, "__ref", "__pf_absent")
	id != "__pf_absent"
	is_string(id)
}

# 関数の VpcConfig（生ドキュメント）。
_pf_lam_vpccfg(name) := c if c := _pf_lam_obj(_pf_lam_props(name), "VpcConfig")

# サブネット / セキュリティグループの VpcId。Ref も GetAtt も構造のまま返すので、
# 同じ VPC を指していれば Rego の値として等しくなる。
_pf_lam_vpc_of(v) := vpc if {
	vpc := object.get(_pf_lam_res_props(_pf_lam_ref(v)), "VpcId", "__pf_absent")
	vpc != "__pf_absent"
}

# EFS マウントターゲットが置かれているサブネットの AZ。
_pf_lam_mt_azs contains az if {
	some id in resources_of_type("AWS::EFS::MountTarget")
	sub := object.get(_pf_lam_res_props(id), "SubnetId", null)
	az := object.get(_pf_lam_res_props(_pf_lam_ref(sub)), "AvailabilityZone", "__pf_absent")
	az != "__pf_absent"
}

# 関数にぶら下がる ProvisionedConcurrencyConfig の割り当て量。
# Version も Alias も FunctionName で関数を指すので、その値ごとに合算できる。
_pf_lam_pc contains [id, fnref, n] if {
	# resources_of_type は配列を返すので集合の和（|）は使えない。
	some id in array.concat(_pf_lam_ver, _pf_lam_alias)
	props := _pf_lam_props(id)
	pcc := _pf_lam_obj(props, "ProvisionedConcurrencyConfig")
	n := object.get(pcc, "ProvisionedConcurrentExecutions", "__pf_absent")
	is_number(n)
	fnref := object.get(props, "FunctionName", "__pf_absent")
	fnref != "__pf_absent"
}

# 「文字列として存在する」ときだけ返す。object.get の既定値を空文字にすると
# キーが無いテンプレートでも判定が走り、パック全体の pass に誤発火する
# （2026-09-07 に image-uri-private-ecr と recursive-loop-enum で実測）。
_pf_lam_str(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
	is_string(v)
}
