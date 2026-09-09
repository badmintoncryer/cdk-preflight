package cdk_preflight

import rego.v1

# DistributionConfig の中身。Distribution 系ルールのほぼ全部が入口にする。
_pf_cflib_config(name) := v if {
	some it in flatten_list(name, "Properties.DistributionConfig")
	v := it.value
}

# 任意のリソースの Properties.<root>。子リソース型（CachePolicy など）用。
_pf_cflib_props(name, root) := v if {
	some it in flatten_list(name, sprintf("Properties.%s", [root]))
	v := it.value
}

# DefaultCacheBehavior と CacheBehaviors[] を 1 本のリストに束ねる。
# CloudFront の制約はほぼ全部「どのビヘイビアでも同じように効く」ので、
# 個々のルールが 2 回ずつ書かなくて済むようにここへ寄せている。
_pf_cflib_behaviors(name) := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior", "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index]), "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)

_pf_cflib_origins(name) := [{"path": sprintf("Properties.DistributionConfig.Origins.%d", [it.index]), "value": it.value} |
	some it in flatten_list(name, "Properties.DistributionConfig.Origins")]

_pf_cflib_origin_groups(name) := [{"path": sprintf("Properties.DistributionConfig.OriginGroups.Items.%d", [it.index]), "value": it.value} |
	some it in flatten_list(name, "Properties.DistributionConfig.OriginGroups.Items")]

# TargetOriginId が指せる Id の全体（Origins と OriginGroups の両方）。
_pf_cflib_origin_ids(name) := a | b if {
	a := {id |
		some o in _pf_cflib_origins(name)
		id := object.get(o.value, "Id", null)
		is_string(id)
	}
	b := {id |
		some g in _pf_cflib_origin_groups(name)
		id := object.get(g.value, "Id", null)
		is_string(id)
	}
}
