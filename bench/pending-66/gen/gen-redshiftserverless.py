#!/usr/bin/env python3
"""Generator for the Redshift Serverless rules (issue #66, slice C5).

Writes rules/redshiftserverless/<rule-id>/{rule.rego,meta.yaml,templates/{fail,pass}.template.json},
rules/_lib/redshiftserverless.rego and the boundary-exception line. Fixes go here, then re-run:

    python3 gen-redshiftserverless.py /home/user/wt-redshiftserverless
"""
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/home/user/wt-redshiftserverless"
SERVICE = "redshiftserverless"
ADDED_ON = "2026-09-22"
NS_TYPE = "AWS::RedshiftServerless::Namespace"
WG_TYPE = "AWS::RedshiftServerless::Workgroup"
CFN_NS = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshiftserverless-namespace.html"
API_WG = "https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateWorkgroup.html"
API_NS = "https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateNamespace.html"
CAPACITY = "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-capacity.html"
PERF = "https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_PerformanceTarget.html"
KNOWN = "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-known-issues.html"

HEADER = "package cdk_preflight\n\nimport rego.v1\n\n"


def ns(name, **props):
    return {"Type": NS_TYPE, "Properties": {"NamespaceName": name, **props}}


def wg(name, ns_logical, **props):
    return {"Type": WG_TYPE, "Properties": {"WorkgroupName": name, "NamespaceName": {"Ref": ns_logical}, **props}}


def role(services=("redshift.amazonaws.com", "redshift-serverless.amazonaws.com")):
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": list(services)}, "Action": "sts:AssumeRole"}],
            }
        },
    }


def getatt(logical, attr):
    return {"Fn::GetAtt": [logical, attr]}


def tpl(resources):
    return {"Resources": resources}


def yaml_str(s):
    # JSON double-quoted scalars are valid YAML double-quoted scalars.
    return json.dumps(s, ensure_ascii=False)


def meta(rule_id, types, title, source, evidence, upstream="none"):
    return (
        f"id: {rule_id}\n"
        f"service: {SERVICE}\n"
        f"benchRegion: us-east-1\n"
        f"resourceTypes: [{', '.join(types)}]\n"
        f"severity: ERROR\n"
        f"title: {yaml_str(title)}\n"
        f"constraintSource: {source}\n"
        f"upstream: {upstream}\n"
        f"repro:\n"
        f"  method: real-deploy\n"
        f"  evidence: {yaml_str(evidence)}\n"
        f"addedOn: {ADDED_ON}\n"
    )


def diag(rule_id, path, msg, fix, url, body, helpers=""):
    return (
        HEADER
        + helpers
        + f'violation contains make_diag_full("{rule_id}", "ERROR", name,\n'
        + f"\t{path},\n"
        + f"\t{msg},\n"
        + f"\t{yaml_str(fix)},\n"
        + f"\t{yaml_str(url)}) if {{\n"
        + body
        + "}\n"
    )


def q(s):
    """Rego double-quoted string literal."""
    return json.dumps(s, ensure_ascii=False)


LIB = HEADER + """# Shared helpers for the Redshift Serverless rules. Absence can only be proven on
# the preprocessed document (resolve() is undefined both for a missing key and for
# an unresolvable token, see AGENTS.md), so "is the property written" always goes
# through _pf_rsslib_has. Loaded ahead of every rule (BUNDLED_LIBS); never emits
# diagnostics.

_pf_rsslib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_rsslib_has(name, k) if {
	object.get(_pf_rsslib_props(name), k, "__pf_absent") != "__pf_absent"
}

_pf_rsslib_get(name, k) := v if {
	v := object.get(_pf_rsslib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

# True only when the document literally says true (an unresolved token is neither).
_pf_rsslib_true(name, k) if _pf_rsslib_get(name, k) == true

_pf_rsslib_true(name, k) if _pf_rsslib_get(name, k) == "true"

_pf_rsslib_false(name, k) if _pf_rsslib_get(name, k) == false

_pf_rsslib_false(name, k) if _pf_rsslib_get(name, k) == "false"

# A list element as flatten_list hands it over: a literal string, or the marker
# object of a Ref / GetAtt, which carries the target's logical id in __ref.
_pf_rsslib_ref(v) := v if is_string(v)

_pf_rsslib_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}
"""

RULES = {}

# ---------------------------------------------------------------- 1. admin password exclusive
rid = "pf-redshiftserverless-admin-password-exclusive"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.AdminUserPassword"),
        q('ManageAdminPassword is true and AdminUserPassword is also set; CreateNamespace fails with "The AdminUserPassword parameter cannot be provided if ManagedAdminPassword is true."'),
        "Drop AdminUserPassword and let Secrets Manager hold the credential, or set ManageAdminPassword to false",
        CFN_NS,
        f'\tsome name in resources_of_type("{NS_TYPE}")\n'
        '\t_pf_rsslib_true(name, "ManageAdminPassword")\n'
        '\t_pf_rsslib_has(name, "AdminUserPassword")\n',
    ),
    fail=tpl({"NS": ns("pfrss-adminpw-f", AdminUsername="benchadmin", ManageAdminPassword=True, AdminUserPassword="Benchpass123")}),
    pass_=tpl({"NS": ns("pfrss-adminpw-p", AdminUsername="benchadmin", ManageAdminPassword=True)}),
    meta=meta(
        rid, [NS_TYPE], "ManageAdminPassword cannot be combined with AdminUserPassword", CFN_NS,
        'api-probe 2026-09-15 us-east-1: CreateNamespace with manageAdminPassword=true and adminUserPassword -> "ValidationException: The AdminUserPassword parameter cannot be provided if ManagedAdminPassword is true." (#66 phase B); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 2. admin secret kms requires manage
rid = "pf-redshiftserverless-admin-secret-kms-requires-manage"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.AdminPasswordSecretKmsKeyId"),
        q('AdminPasswordSecretKmsKeyId is set but ManageAdminPassword is not true; CreateNamespace fails with "The AdminPasswordSecretKmsKeyId parameter cannot be provided unless ManagedAdminPassword is true."'),
        "Set ManageAdminPassword to true, or drop AdminPasswordSecretKmsKeyId",
        CFN_NS,
        f'\tsome name in resources_of_type("{NS_TYPE}")\n'
        '\t_pf_rsslib_has(name, "AdminPasswordSecretKmsKeyId")\n'
        '\t_pf_rsskms_unmanaged(name)\n',
        helpers=(
            "# Absent or literally false. An unresolved token is neither, so the rule skips it.\n"
            '_pf_rsskms_unmanaged(name) if not _pf_rsslib_has(name, "ManageAdminPassword")\n\n'
            '_pf_rsskms_unmanaged(name) if _pf_rsslib_false(name, "ManageAdminPassword")\n\n'
        ),
    ),
    fail=tpl({"NS": ns("pfrss-adminkms-f", AdminUsername="benchadmin", AdminPasswordSecretKmsKeyId="alias/aws/secretsmanager")}),
    pass_=tpl({"NS": ns("pfrss-adminkms-p", AdminUsername="benchadmin", ManageAdminPassword=True, AdminPasswordSecretKmsKeyId="alias/aws/secretsmanager")}),
    meta=meta(
        rid, [NS_TYPE], "AdminPasswordSecretKmsKeyId requires ManageAdminPassword", CFN_NS,
        'api-probe 2026-09-15 us-east-1: CreateNamespace with adminPasswordSecretKmsKeyId and no manageAdminPassword -> "ValidationException: The AdminPasswordSecretKmsKeyId parameter cannot be provided unless ManagedAdminPassword is true." (#66 phase B); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 3. base capacity floor
rid = "pf-redshiftserverless-base-capacity-floor"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.BaseCapacity"),
        'sprintf("BaseCapacity %v is below the 4 RPU minimum; CreateWorkgroup fails with \\"The base capacity can\'t be less than 4 RPUs.\\"", [n])',
        "Set BaseCapacity to 4, 8, or a multiple of 8",
        CAPACITY,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\tn := to_number(resolve(name, "Properties.BaseCapacity"))\n'
        "\tn < 4\n",
    ),
    fail=tpl({"NS": ns("pfrss-bcfloor-f"), "WG": wg("pfrss-bcfloor-f", "NS", BaseCapacity=3)}),
    pass_=tpl({"NS": ns("pfrss-bcfloor-p"), "WG": wg("pfrss-bcfloor-p", "NS", BaseCapacity=4)}),
    meta=meta(
        rid, [WG_TYPE], "Workgroup BaseCapacity must be at least 4 RPUs", CAPACITY,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup baseCapacity 3 -> "ValidationException: The base capacity can\'t be less than 4 RPUs." (#66 phase B); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 4. base capacity step
rid = "pf-redshiftserverless-base-capacity-step"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.BaseCapacity"),
        'sprintf("BaseCapacity %v is above 8 RPUs but not a multiple of 8; CreateWorkgroup fails with \\"The base capacity must be a multiple of 8.\\"", [n])',
        "Above 8 RPUs, BaseCapacity moves in steps of 8 (16, 24, ..., 512; 32-RPU steps above 512 where the region allows it)",
        CAPACITY,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\tn := to_number(resolve(name, "Properties.BaseCapacity"))\n'
        "\tn > 8\n"
        "\tn % 8 != 0\n",
        helpers=(
            "# 4 and 8 are both valid (the 4-8 band moves in steps of 4); the rule only judges the\n"
            "# band above 8, where every valid value (8-512 in steps of 8, 512-1024 in steps of 32)\n"
            "# is a multiple of 8. Values below 4 belong to pf-redshiftserverless-base-capacity-floor.\n"
        ),
    ),
    fail=tpl({"NS": ns("pfrss-bcstep-f"), "WG": wg("pfrss-bcstep-f", "NS", BaseCapacity=9)}),
    pass_=tpl({
        "NS8": ns("pfrss-bcstep-p8"), "WG8": wg("pfrss-bcstep-p8", "NS8", BaseCapacity=8),
        "NS16": ns("pfrss-bcstep-p16"), "WG16": wg("pfrss-bcstep-p16", "NS16", BaseCapacity=16),
    }),
    meta=meta(
        rid, [WG_TYPE], "Workgroup BaseCapacity above 8 must be a multiple of 8", CAPACITY,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup baseCapacity 12 -> "ValidationException: The base capacity must be a multiple of 8." (#66 phase B; the fail fixture sits on 9, the nearest violation above 8, and the pass fixture on 8 and 16); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 5. default IAM role in IamRoles
rid = "pf-redshiftserverless-default-iam-role-in-iam-roles"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.DefaultIamRoleArn"),
        'sprintf("DefaultIamRoleArn %v is not listed in IamRoles %v; CreateNamespace fails with \\"Invalid default IAM Role ... The IAM roles list isnt specified or it doesnt contain a default IAM Role\\"", [d, roles])',
        "Add the default role to IamRoles as well (IamRoles must contain every role the namespace uses, the default included)",
        API_NS,
        f'\tsome name in resources_of_type("{NS_TYPE}")\n'
        '\td := resolve(name, "Properties.DefaultIamRoleArn")\n'
        "\t_pf_rssdir_comparable(d, d)\n"
        "\tnot _pf_rssdir_odd[name]\n"
        "\tnot _pf_rssdir_role[[name, d]]\n"
        "\troles := [r | _pf_rssdir_role[[name, r]]]\n",
        helpers=(
            "# resolve() turns a Ref / GetAtt into the target's logical id and leaves a literal ARN\n"
            "# as is, so both sides are compared in the same currency only when they are of the same\n"
            "# kind: two logical ids of resources in this template, or two literal ARNs. A mixed or\n"
            "# unresolvable list (Fn::Sub over a resource, a Ref to a list parameter) cannot be judged.\n"
            "_pf_rssdir_lit(v) if {\n"
            "\tis_string(v)\n"
            '\tstartswith(v, "arn:")\n'
            "}\n\n"
            "_pf_rssdir_ref(v) if {\n"
            "\tis_string(v)\n"
            "\tinput.resources[v]\n"
            "}\n\n"
            "_pf_rssdir_comparable(a, b) if {\n"
            "\t_pf_rssdir_lit(a)\n"
            "\t_pf_rssdir_lit(b)\n"
            "}\n\n"
            "_pf_rssdir_comparable(a, b) if {\n"
            "\t_pf_rssdir_ref(a)\n"
            "\t_pf_rssdir_ref(b)\n"
            "}\n\n"
            "# The raw IamRoles list; an absent list reads as empty, which the service rejects too\n"
            '# ("The IAM roles list isnt specified").\n'
            '_pf_rssdir_arr(name) := object.get(_pf_rsslib_props(name), "IamRoles", [])\n\n'
            "# Namespaces whose IamRoles the rule cannot compare with the default role.\n"
            "_pf_rssdir_odd contains name if {\n"
            f'\tsome name in resources_of_type("{NS_TYPE}")\n'
            "\tnot is_array(_pf_rssdir_arr(name))\n"
            "}\n\n"
            "_pf_rssdir_odd contains name if {\n"
            f'\tsome name in resources_of_type("{NS_TYPE}")\n'
            "\tarr := _pf_rssdir_arr(name)\n"
            "\tis_array(arr)\n"
            '\td := resolve(name, "Properties.DefaultIamRoleArn")\n'
            "\tsome i, _ in arr\n"
            '\tnot _pf_rssdir_comparable(d, resolve(name, sprintf("Properties.IamRoles.%d", [i])))\n'
            "}\n\n"
            "# [namespace, resolved role] for every entry of IamRoles.\n"
            "_pf_rssdir_role contains [name, r] if {\n"
            f'\tsome name in resources_of_type("{NS_TYPE}")\n'
            "\tarr := _pf_rssdir_arr(name)\n"
            "\tis_array(arr)\n"
            "\tsome i, _ in arr\n"
            '\tr := resolve(name, sprintf("Properties.IamRoles.%d", [i]))\n'
            "\tis_string(r)\n"
            "}\n\n"
        ),
    ),
    fail=tpl({
        "RoleA": role(), "RoleB": role(),
        "NS": ns("pfrss-defrole-f", DefaultIamRoleArn=getatt("RoleA", "Arn"), IamRoles=[getatt("RoleB", "Arn")]),
    }),
    pass_=tpl({
        "RoleA": role(), "RoleB": role(),
        "NS": ns("pfrss-defrole-p", DefaultIamRoleArn=getatt("RoleA", "Arn"), IamRoles=[getatt("RoleA", "Arn"), getatt("RoleB", "Arn")]),
    }),
    meta=meta(
        rid, [NS_TYPE], "DefaultIamRoleArn must also be listed in IamRoles", API_NS,
        'api-probe 2026-09-15 us-east-1: CreateNamespace defaultIamRoleArn role/pf66-a with iamRoles [role/pf66-b] -> "ValidationException: Invalid default IAM Role \'arn:aws:iam::...:role/pf66-a\'. The IAM roles list isnt specified or it doesnt contain a default IAM Role: [arn:aws:iam::...:role/pf66-b]." (#66 phase B; the fixtures create the two roles with a redshift / redshift-serverless trust policy so the service reaches this check); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 6. log exports enum (gray zone: W3030)
rid = "pf-redshiftserverless-log-exports-enum"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.LogExports"),
        'sprintf("LogExports contains %v, which is not one of useractivitylog / userlog / connectionlog; CreateNamespace fails with \\"Value \'[querylog]\' at \'logExports\' failed to satisfy constraint: Member must satisfy enum value set: [connectionlog, useractivitylog, userlog]\\"", [v])',
        "Use only useractivitylog, userlog and connectionlog",
        API_NS,
        f'\tsome name in resources_of_type("{NS_TYPE}")\n'
        '\tsome it in flatten_list(name, "Properties.LogExports")\n'
        "\tv := it.value\n"
        "\tis_string(v)\n"
        "\tnot v in _pf_rsslog_allowed\n",
        helpers=(
            "# Gray zone: the bundled engine knows this enum but reports it as W3030 (WARN), which\n"
            "# blocks nothing. Retires with the upstream severity fix (meta upstream: pending-engine).\n"
            '_pf_rsslog_allowed := {"useractivitylog", "userlog", "connectionlog"}\n\n'
        ),
    ),
    fail=tpl({"NS": ns("pfrss-logexp-f", LogExports=["querylog"])}),
    pass_=tpl({"NS": ns("pfrss-logexp-p", LogExports=["useractivitylog", "userlog", "connectionlog"])}),
    meta=meta(
        rid, [NS_TYPE], "LogExports accepts only useractivitylog, userlog and connectionlog", API_NS,
        'api-probe 2026-09-15 us-east-1: CreateNamespace logExports [querylog] -> "ValidationException: 1 validation error detected: Value \'[querylog]\' at \'logExports\' failed to satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: [connectionlog, useractivitylog, userlog]]" (#66 phase B). Gray zone: the bundled engine reports the enum only as W3030/WARN, so nothing blocks the deploy; bench: PENDING',
        upstream="pending-engine",
    ),
)

# ---------------------------------------------------------------- 7. max capacity >= base capacity
rid = "pf-redshiftserverless-max-capacity-ge-base"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.MaxCapacity"),
        'sprintf("MaxCapacity %v is lower than BaseCapacity %v; CreateWorkgroup fails with \\"The base capacity can\'t be more than 24 RPUs.\\" (the service words it from the base side)", [m, b])',
        "Raise MaxCapacity to at least BaseCapacity, or lower BaseCapacity",
        API_WG,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\tb := to_number(resolve(name, "Properties.BaseCapacity"))\n'
        '\tm := to_number(resolve(name, "Properties.MaxCapacity"))\n'
        "\tm < b\n",
    ),
    fail=tpl({"NS": ns("pfrss-maxcap-f"), "WG": wg("pfrss-maxcap-f", "NS", BaseCapacity=32, MaxCapacity=24)}),
    pass_=tpl({"NS": ns("pfrss-maxcap-p"), "WG": wg("pfrss-maxcap-p", "NS", BaseCapacity=32, MaxCapacity=32)}),
    meta=meta(
        rid, [WG_TYPE], "Workgroup MaxCapacity must not be lower than BaseCapacity", API_WG,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup baseCapacity 32 / maxCapacity 24 -> "ValidationException: The base capacity can\'t be more than 24 RPUs." (#66 phase B; the service phrases the check from the base side); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 8. port range (both bands, both ends)
rid = "pf-redshiftserverless-port-range"
PORT_MSG = "Amazon Redshift Serverless doesn't support ports outside of the range (5431-5455) and (8191-8215)"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.Port"),
        'sprintf("Port %v is outside 5431-5455 and 8191-8215; CreateWorkgroup fails with \\"' + PORT_MSG + ': 5430.\\"", [n])',
        "Pick a port between 5431 and 5455 or between 8191 and 8215 (the default is 5439)",
        API_WG,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\tn := to_number(resolve(name, "Properties.Port"))\n'
        "\t_pf_rssport_out(n)\n",
        helpers=(
            "_pf_rssport_out(n) if n < 5431\n\n"
            "_pf_rssport_out(n) if {\n"
            "\tn > 5455\n"
            "\tn < 8191\n"
            "}\n\n"
            "_pf_rssport_out(n) if n > 8215\n\n"
        ),
    ),
    fail=tpl({
        "NS1": ns("pfrss-port-f1"), "WG1": wg("pfrss-port-f1", "NS1", Port=5430),
        "NS2": ns("pfrss-port-f2"), "WG2": wg("pfrss-port-f2", "NS2", Port=5456),
        "NS3": ns("pfrss-port-f3"), "WG3": wg("pfrss-port-f3", "NS3", Port=8190),
        "NS4": ns("pfrss-port-f4"), "WG4": wg("pfrss-port-f4", "NS4", Port=8216),
    }),
    pass_=tpl({
        "NS1": ns("pfrss-port-p1"), "WG1": wg("pfrss-port-p1", "NS1", Port=5431),
        "NS2": ns("pfrss-port-p2"), "WG2": wg("pfrss-port-p2", "NS2", Port=5455),
        "NS3": ns("pfrss-port-p3"), "WG3": wg("pfrss-port-p3", "NS3", Port=8191),
        "NS4": ns("pfrss-port-p4"), "WG4": wg("pfrss-port-p4", "NS4", Port=8215),
    }),
    meta=meta(
        rid, [WG_TYPE], "Workgroup Port must be within 5431-5455 or 8191-8215", API_WG,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup port 5430 -> "ValidationException: ' + PORT_MSG + ': 5430."; port 5456 -> same message ending ": 5456." (#66 phase B; the fail fixture carries all four edges 5430 / 5456 / 8190 / 8216 and the pass fixture 5431 / 5455 / 8191 / 8215, one namespace per workgroup); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 9. price performance level enum
rid = "pf-redshiftserverless-price-performance-level-enum"
RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.PricePerformanceTarget.Level"),
        'sprintf("PricePerformanceTarget.Level %v is not one of 1, 25, 50, 75 or 100; CreateWorkgroup fails with \\"The specified pricePerformanceTargetLevel is invalid. Valid levels are 1, 25, 50, 75, and 100.\\"", [l])',
        "Use one of the five levels: 1 (lowest cost), 25, 50, 75 or 100 (highest performance)",
        PERF,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\tl := to_number(resolve(name, "Properties.PricePerformanceTarget.Level"))\n'
        "\tnot l in _pf_rssppt_levels\n",
        helpers='_pf_rssppt_levels := {1, 25, 50, 75, 100}\n\n',
    ),
    fail=tpl({"NS": ns("pfrss-ppt-f"), "WG": wg("pfrss-ppt-f", "NS", PricePerformanceTarget={"Level": 30, "Status": "ENABLED"})}),
    pass_=tpl({"NS": ns("pfrss-ppt-p"), "WG": wg("pfrss-ppt-p", "NS", PricePerformanceTarget={"Level": 25, "Status": "ENABLED"})}),
    meta=meta(
        rid, [WG_TYPE], "PricePerformanceTarget Level must be 1, 25, 50, 75 or 100", PERF,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup pricePerformanceTarget level 30 -> "ValidationException: The specified pricePerformanceTargetLevel is invalid. Valid levels are 1, 25, 50, 75, and 100." (#66 phase B); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 10. snapshot copy destination region = own region
rid = "pf-redshiftserverless-snapshot-copy-destination-region-self"
RULES[rid] = dict(
    rego=diag(
        rid,
        'sprintf("Properties.SnapshotCopyConfigurations.%d.DestinationRegion", [i])',
        'sprintf("DestinationRegion %s is the region the namespace itself deploys to; the copy configuration fails with \\"Invalid Region \'%s\'.\\"", [r, r])',
        "Point the snapshot copy at a different region, or drop the SnapshotCopyConfigurations entry",
        CFN_NS,
        f'\tsome name in resources_of_type("{NS_TYPE}")\n'
        "\tregion := data.cdk_preflight.deploy_region\n"
        "\tis_string(region)\n"
        '\tarr := object.get(_pf_rsslib_props(name), "SnapshotCopyConfigurations", [])\n'
        "\tis_array(arr)\n"
        "\tsome i, _ in arr\n"
        '\tr := resolve(name, sprintf("Properties.SnapshotCopyConfigurations.%d.DestinationRegion", [i]))\n'
        "\tr == region\n",
        helpers=(
            "# data.cdk_preflight.deploy_region is defined only when the enforce plugin knows the\n"
            "# app's concrete region (see src/private/enforce.ts); without it the reference is\n"
            "# undefined and this rule skips. resolve() flattens Ref AWS::Region, so a copy aimed at\n"
            "# the pseudo parameter is caught as well as a literal.\n"
        ),
    ),
    fail=tpl({"NS": ns("pfrss-snapcopy-f", SnapshotCopyConfigurations=[{"DestinationRegion": "us-east-1"}])}),
    pass_=tpl({"NS": ns("pfrss-snapcopy-p", SnapshotCopyConfigurations=[{"DestinationRegion": "us-west-2"}])}),
    meta=meta(
        rid, [NS_TYPE], "Snapshot copy DestinationRegion must differ from the namespace region", CFN_NS,
        'api-probe 2026-09-15 us-east-1: CreateSnapshotCopyConfiguration destinationRegion us-east-1 from us-east-1 -> "ValidationException: Invalid Region \'us-east-1\'." (#66 phase B; the CloudFormation handler calls it after CreateNamespace, so the fail stack creates the namespace first and rolls it back). Evaluates only in enforce mode with a concrete app region (deploy_region injection); silent otherwise. Test fixtures assume the harness region us-east-1; bench: PENDING',
    ),
)

# ---------------------------------------------------------------- 11. workgroup subnets span < 3 AZs with EVR on
rid = "pf-redshiftserverless-workgroup-subnet-az-count"
AZ_MSG = "There aren't enough free IP addresses in subnets to allow this operation. Make sure that there are at least 37 free IP addresses in 3 subnets. Each subnet should be in a different Availability Zone."


def vpc_fixture(n_subnets, suffix):
    res = {
        "VPC": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
        "SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "cdk-preflight redshift serverless bench", "VpcId": {"Ref": "VPC"}}},
    }
    azs = ["us-east-1a", "us-east-1b", "us-east-1c"]
    for k in range(n_subnets):
        res[f"Subnet{k + 1}"] = {
            "Type": "AWS::EC2::Subnet",
            "Properties": {"VpcId": {"Ref": "VPC"}, "CidrBlock": f"10.0.{k}.0/24", "AvailabilityZone": azs[k]},
        }
    res["NS"] = ns(f"pfrss-azcount-{suffix}")
    res["WG"] = wg(
        f"pfrss-azcount-{suffix}", "NS",
        EnhancedVpcRouting=True,
        SubnetIds=[{"Ref": f"Subnet{k + 1}"} for k in range(n_subnets)],
        SecurityGroupIds=[{"Ref": "SG"}],
    )
    return tpl(res)


RULES[rid] = dict(
    rego=diag(
        rid,
        q("Properties.SubnetIds"),
        'sprintf("EnhancedVpcRouting is on but the subnets span only %v availability zone(s) %v; CreateWorkgroup fails with \\"' + AZ_MSG + '\\"", [count(azs), azs])',
        "Give the workgroup subnets in at least three availability zones, each with 37 or more free addresses",
        KNOWN,
        f'\tsome name in resources_of_type("{WG_TYPE}")\n'
        '\t_pf_rsslib_true(name, "EnhancedVpcRouting")\n'
        '\tsubs := [s | some s in flatten_list(name, "Properties.SubnetIds")]\n'
        "\tcount(subs) > 0\n"
        "\tevery s in subs {\n"
        "\t\t_pf_rssaz_az(s.value)\n"
        "\t}\n"
        "\tazs := {az | some s in subs; az := _pf_rssaz_az(s.value)}\n"
        "\tcount(azs) < 3\n",
        helpers=(
            "# The zone of a subnet defined in this template. resolve() flattens Fn::Select over\n"
            "# Fn::GetAZs to the region's real zone names (measured 2026-09-22), so a CDK Vpc with\n"
            "# maxAzs: 2 is judged like a literal. Imported subnet ids cannot be, and the rule stays\n"
            "# silent unless every subnet of the workgroup resolves to a zone.\n"
            "_pf_rssaz_az(v) := az if {\n"
            "\tsub := _pf_rsslib_ref(v)\n"
            '\tsub in resources_of_type("AWS::EC2::Subnet")\n'
            '\taz := resolve(sub, "Properties.AvailabilityZone")\n'
            "\tis_string(az)\n"
            "\tnot input.resources[az]\n"
            "}\n\n"
        ),
    ),
    fail=vpc_fixture(2, "f"),
    pass_=vpc_fixture(3, "p"),
    meta=meta(
        rid, [WG_TYPE, "AWS::EC2::Subnet"], "Enhanced VPC routing needs subnets in three availability zones", KNOWN,
        'api-probe 2026-09-15 us-east-1: CreateWorkgroup enhancedVpcRouting=true with subnets in 2 AZs -> "ValidationException: ' + AZ_MSG + '"; control enhancedVpcRouting=false with the same 2 subnets -> accepted (#66 phase B; the message mixes the free-IP count into the zone requirement, so the fixtures use /24 subnets and only the zone count is violated); bench: PENDING',
    ),
)

# ---------------------------------------------------------------- write
BOUNDARY_EXCEPTION = (
    "pf-redshiftserverless-max-capacity-ge-base  BaseCapacity / MaxCapacity は 8 RPU 刻み（8-512）なので、最も近い違反値の差は 8 であって 1 ではない"
    "（fail は 32/24 に乗せてある。B の api-probe も同じ値で \"The base capacity can't be more than 24 RPUs.\"）。pass は 32/32 で同値に乗っている"
)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    write(os.path.join(ROOT, "rules", "_lib", f"{SERVICE}.rego"), LIB)
    for rule_id, r in RULES.items():
        d = os.path.join(ROOT, "rules", SERVICE, rule_id)
        write(os.path.join(d, "rule.rego"), r["rego"])
        write(os.path.join(d, "meta.yaml"), r["meta"])
        write(os.path.join(d, "templates", "fail.template.json"), json.dumps(r["fail"], indent=2) + "\n")
        write(os.path.join(d, "templates", "pass.template.json"), json.dumps(r["pass_"], indent=2) + "\n")
    exc = os.path.join(ROOT, "rules", "_boundary-exceptions.txt")
    with open(exc, encoding="utf-8") as f:
        lines = f.read()
    if "pf-redshiftserverless-max-capacity-ge-base" not in lines:
        with open(exc, "a", encoding="utf-8") as f:
            if not lines.endswith("\n"):
                f.write("\n")
            f.write(BOUNDARY_EXCEPTION + "\n")
    print(f"wrote {len(RULES)} rules + lib under {ROOT}")
    print("\n".join(RULES))


if __name__ == "__main__":
    main()
