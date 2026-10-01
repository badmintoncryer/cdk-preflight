package cdk_preflight

import rego.v1

# AWS::Cassandra::Table / Type の列型（CQL 型文字列）を読むヘルパー。診断は出さない。
#
# 型文字列は生の properties から読む（is_string で Ref / Fn::Sub / Fn::Join のマーカーを落とす。
# resolve() は Ref を論理 ID の文字列に変えるので、UDT 名と取り違える）。
# Rego は再帰できないので、字句に切ってから「各識別子の深さ」と「直近の親（それを開いた < の
# 直前の識別子）」を数えて木の代わりにする。

# 組み込みのスカラー型（2026-10-01 に CreateType の型名で拒否された 20 個 + inet。duration は受理）
_pf_cass_scalars := {
	"ascii", "bigint", "blob", "boolean", "counter", "date", "decimal", "double", "duration",
	"float", "inet", "int", "smallint", "text", "time", "timestamp", "timeuuid", "tinyint",
	"uuid", "varchar", "varint",
}

_pf_cass_collections := {"list", "set", "map"}

_pf_cass_keywords := {"list", "set", "map", "tuple", "frozen"}

_pf_cass_toks(s) := regex.find_n(`"[^"]*"|[A-Za-z0-9_.]+|[<>,]|[^\sA-Za-z0-9_.<>,"]`, s, -1)

_pf_cass_is_ident(t) if regex.match(`^("|[A-Za-z0-9_.])`, t)

_pf_cass_name(t) := lower(trim(t, `"`))

# toks[i] の手前で開いたままの < の数
_pf_cass_depth(toks, i) := count([1 | some k, t in toks; k < i; t == "<"]) - count([1 | some k, t in toks; k < i; t == ">"])

# 識別子ノード: i（位置）, n（小文字・引用符除去）, d（深さ）, p（親の位置。最上位は -1）, open（直後が <）
_pf_cass_nodes(s) := [node |
	toks := _pf_cass_toks(s)
	some i, t in toks
	_pf_cass_is_ident(t)
	d := _pf_cass_depth(toks, i)
	node := {"i": i, "n": _pf_cass_name(t), "d": d, "p": _pf_cass_parent(toks, i, d), "open": _pf_cass_opens(toks, i)}
]

_pf_cass_opens(toks, i) := true if toks[i + 1] == "<"

_pf_cass_opens(toks, i) := false if not toks[i + 1] == "<"

_pf_cass_parent(_, _, d) := -1 if d == 0

_pf_cass_parent(toks, i, d) := max(js) if {
	d > 0
	js := [j |
		some j, _ in toks
		j < i
		toks[j + 1] == "<"
		_pf_cass_depth(toks, j) == d - 1
	]
	count(js) > 0
}

_pf_cass_node_name(nodes, i) := n.n if {
	some n in nodes
	n.i == i
}

# 列（とフィールド）の生のオブジェクト: [resource, kind, path, column]。kind は pk / ck / reg / field、
# path は列オブジェクトまでのパス（型は path + ".ColumnType" / ".FieldType"）
_pf_cass_rawcol contains [name, kind, sprintf("Properties.%s.%d", [key, i]), c] if {
	some name in resources_of_type("AWS::Cassandra::Table")
	props := input.resources[name].properties
	some pair in [["PartitionKeyColumns", "pk"], ["RegularColumns", "reg"]]
	key := pair[0]
	kind := pair[1]
	cols := object.get(props, key, [])
	is_array(cols)
	some i, c in cols
	is_object(c)
}

_pf_cass_rawcol contains [name, "ck", sprintf("Properties.ClusteringKeyColumns.%d.Column", [i]), c] if {
	some name in resources_of_type("AWS::Cassandra::Table")
	cols := object.get(input.resources[name].properties, "ClusteringKeyColumns", [])
	is_array(cols)
	some i, cc in cols
	is_object(cc)
	c := object.get(cc, "Column", null)
	is_object(c)
}

_pf_cass_rawcol contains [name, "field", sprintf("Properties.Fields.%d", [i]), f] if {
	some name in resources_of_type("AWS::Cassandra::Type")
	fs := object.get(input.resources[name].properties, "Fields", [])
	is_array(fs)
	some i, f in fs
	is_object(f)
}

_pf_cass_typekey(kind) := "FieldType" if kind == "field"

_pf_cass_typekey(kind) := "ColumnType" if kind != "field"

# 型が文字列リテラルの列: [resource, kind, typePath, typeString]
_pf_cass_col contains [name, kind, concat(".", [p, k]), t] if {
	some [name, kind, p, c] in _pf_cass_rawcol
	k := _pf_cass_typekey(kind)
	t := object.get(c, k, null)
	is_string(t)
}

# テンプレート内の AWS::Cassandra::Keyspace の論理 ID（KeyspaceName が Ref か、同名の文字列）
_pf_cass_ks(name) := k if {
	v := object.get(input.resources[name].properties, "KeyspaceName", null)
	is_object(v)
	v.__kind == "resource"
	k := v.__ref
	input.resources[k].resourceType == "AWS::Cassandra::Keyspace"
}

_pf_cass_ks(name) := ks[0] if {
	v := object.get(input.resources[name].properties, "KeyspaceName", null)
	is_string(v)
	ks := [k |
		some k in resources_of_type("AWS::Cassandra::Keyspace")
		object.get(input.resources[k].properties, "KeyspaceName", null) == v
	]
	count(ks) == 1
}

# テンプレート内の UDT: [keyspace の論理 ID, 型名（小文字・引用符除去）, Type の論理 ID]
_pf_cass_udts contains [ks, _pf_cass_name(n), t] if {
	some t in resources_of_type("AWS::Cassandra::Type")
	ks := _pf_cass_ks(t)
	n := object.get(input.resources[t].properties, "TypeName", null)
	is_string(n)
}

# 同じキースペースのテンプレート内 UDT を指す識別子か（自分自身は除く）
_pf_cass_is_udt(name, n) if {
	ks := _pf_cass_ks(name)
	some u in _pf_cass_udts
	u[0] == ks
	u[1] == n
	u[2] != name
}

# name が依存する論理 ID（Ref / GetAtt / DependsOn。3 段まで辿る）
_pf_cass_dep1(name) := {t | some r in input.resources[name].outgoingRefs; t := r.target}

_pf_cass_deps(name) := d if {
	d1 := _pf_cass_dep1(name)
	d2 := {t | some x in d1; some t in object.get(_pf_cass_dep1s, x, set())}
	d3 := {t | some x in d2; some t in object.get(_pf_cass_dep1s, x, set())}
	d := (d1 | d2) | d3
}

_pf_cass_dep1s := {n: ts | some n, res in input.resources; ts := {t | some r in res.outgoingRefs; t := r.target}}

# Table の BillingMode.Mode（BillingMode 省略は ON_DEMAND）。Mode や BillingMode がトークンなら undefined
_pf_cass_mode(name) := "ON_DEMAND" if {
	object.get(input.resources[name].properties, "BillingMode", null) == null
}

_pf_cass_mode(name) := m if {
	bm := object.get(input.resources[name].properties, "BillingMode", null)
	is_object(bm)
	not _pf_cass_tokenish(bm)
	m := object.get(bm, "Mode", "ON_DEMAND")
	is_string(m)
}

_pf_cass_tokenish(o) if {
	some k, _ in o
	startswith(k, "__")
}

_pf_cass_tokenish(o) if {
	some k, _ in o
	startswith(k, "Fn::")
}

# テンプレート内の Keyspace（論理 ID）が MULTI_REGION か
_pf_cass_mr(ks) if {
	rs := object.get(input.resources[ks].properties, "ReplicationSpecification", null)
	is_object(rs)
	object.get(rs, "ReplicationStrategy", null) == "MULTI_REGION"
}
