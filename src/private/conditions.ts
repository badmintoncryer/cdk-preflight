/**
 * Which resources a template switches off with a `Condition` that is false
 * under the same values the engine resolves properties with (parameter
 * defaults and the stack's pseudo parameters).
 *
 * The engine resolves a property through a parameter default, but hands every
 * resource to the rules whatever its `Condition` says (issue #408). A resource
 * whose condition is false under those defaults is never created, so a finding
 * on it is a false positive by construction. Rules cannot see the raw condition
 * expressions (`input.conditions` only carries a lossy summary such as
 * `Not(Equals(?, ""))`), so the enforce plugin evaluates them here, on the raw
 * template, and drops the findings whose resource is switched off.
 *
 * The evaluation is three-valued. Anything it cannot evaluate (a parameter
 * without a default, an unknown pseudo parameter, an intrinsic it does not
 * model) is `undefined`, and an undefined condition keeps the resource — the
 * behaviour before this module existed. Only a condition proven false removes
 * anything.
 */

/** What the stack's own environment says about the pseudo parameters. */
export interface PseudoValues {
  readonly region?: string;
  readonly accountId?: string;
}

type Value = string | number | boolean | Value[] | { [k: string]: unknown };

const UNKNOWN = Symbol('unknown');
type Maybe<T> = T | typeof UNKNOWN;

function partitionOf(region: string): { partition: string; urlSuffix: string } {
  if (region.startsWith('cn-')) return { partition: 'aws-cn', urlSuffix: 'amazonaws.com.cn' };
  if (region.startsWith('us-gov-')) return { partition: 'aws-us-gov', urlSuffix: 'amazonaws.com' };
  if (region.startsWith('us-iso-')) return { partition: 'aws-iso', urlSuffix: 'c2s.ic.gov' };
  if (region.startsWith('us-isob-')) return { partition: 'aws-iso-b', urlSuffix: 'sc2s.sgov.gov' };
  return { partition: 'aws', urlSuffix: 'amazonaws.com' };
}

const CONCRETE_REGION = /^[a-z]{2}(-[a-z]+)+-\d+$/;
const CONCRETE_ACCOUNT = /^\d{12}$/;

/** Parameter types whose value is a list (the `Ref` returns the split list). */
function isListParameter(type: unknown): boolean {
  return typeof type === 'string' && (type === 'CommaDelimitedList' || /^List</.test(type));
}

class Evaluator {
  private readonly conditionCache = new Map<string, Maybe<boolean>>();
  private readonly inProgress = new Set<string>();

  constructor(private readonly template: any, private readonly pseudo: PseudoValues) {}

  /** The value of a condition by name, or UNKNOWN. */
  public condition(name: string): Maybe<boolean> {
    if (this.conditionCache.has(name)) return this.conditionCache.get(name)!;
    const conditions = this.template?.Conditions;
    if (!conditions || typeof conditions !== 'object' || !(name in conditions)) return UNKNOWN;
    if (this.inProgress.has(name)) return UNKNOWN; // a cycle is the engine's problem, not ours
    this.inProgress.add(name);
    const out = this.bool(conditions[name]);
    this.inProgress.delete(name);
    this.conditionCache.set(name, out);
    return out;
  }

  private bool(expr: any): Maybe<boolean> {
    if (typeof expr === 'boolean') return expr;
    if (typeof expr === 'string') {
      if (expr === 'true') return true;
      if (expr === 'false') return false;
      return UNKNOWN;
    }
    if (!expr || typeof expr !== 'object' || Array.isArray(expr)) return UNKNOWN;
    const keys = Object.keys(expr);
    if (keys.length !== 1) return UNKNOWN;
    const [fn] = keys;
    const arg = expr[fn];
    switch (fn) {
      case 'Condition':
        return typeof arg === 'string' ? this.condition(arg) : UNKNOWN;
      case 'Fn::Not': {
        if (!Array.isArray(arg) || arg.length !== 1) return UNKNOWN;
        const v = this.bool(arg[0]);
        return v === UNKNOWN ? UNKNOWN : !v;
      }
      case 'Fn::And': {
        if (!Array.isArray(arg) || arg.length < 2) return UNKNOWN;
        const vs = arg.map((a) => this.bool(a));
        if (vs.some((v) => v === false)) return false;
        return vs.every((v) => v === true) ? true : UNKNOWN;
      }
      case 'Fn::Or': {
        if (!Array.isArray(arg) || arg.length < 2) return UNKNOWN;
        const vs = arg.map((a) => this.bool(a));
        if (vs.some((v) => v === true)) return true;
        return vs.every((v) => v === false) ? false : UNKNOWN;
      }
      case 'Fn::Equals': {
        if (!Array.isArray(arg) || arg.length !== 2) return UNKNOWN;
        const a = this.value(arg[0]);
        const b = this.value(arg[1]);
        if (a === UNKNOWN || b === UNKNOWN) return UNKNOWN;
        return scalarText(a) !== undefined && scalarText(b) !== undefined
          ? scalarText(a) === scalarText(b)
          : JSON.stringify(a) === JSON.stringify(b);
      }
      default:
        return UNKNOWN;
    }
  }

  /** The value an expression has under the defaults, or UNKNOWN. */
  private value(expr: any): Maybe<Value> {
    if (typeof expr === 'string' || typeof expr === 'number' || typeof expr === 'boolean') return expr;
    if (Array.isArray(expr)) {
      const out: Value[] = [];
      for (const e of expr) {
        const v = this.value(e);
        if (v === UNKNOWN) return UNKNOWN;
        out.push(v);
      }
      return out;
    }
    if (!expr || typeof expr !== 'object') return UNKNOWN;
    const keys = Object.keys(expr);
    if (keys.length !== 1) return UNKNOWN;
    const [fn] = keys;
    const arg = expr[fn];
    switch (fn) {
      case 'Ref':
        return typeof arg === 'string' ? this.ref(arg) : UNKNOWN;
      case 'Condition': {
        const v = this.condition(arg);
        return v === UNKNOWN ? UNKNOWN : v;
      }
      case 'Fn::Select': {
        if (!Array.isArray(arg) || arg.length !== 2) return UNKNOWN;
        const idx = this.value(arg[0]);
        const list = this.value(arg[1]);
        const i = typeof idx === 'number' ? idx : typeof idx === 'string' && /^\d+$/.test(idx) ? Number(idx) : NaN;
        if (!Array.isArray(list) || !Number.isInteger(i) || i < 0 || i >= list.length) return UNKNOWN;
        return list[i];
      }
      case 'Fn::Split': {
        if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string' || arg[0] === '') return UNKNOWN;
        const s = this.value(arg[1]);
        return typeof s === 'string' ? s.split(arg[0]) : UNKNOWN;
      }
      case 'Fn::Join': {
        if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string') return UNKNOWN;
        const parts = this.value(arg[1]);
        if (!Array.isArray(parts)) return UNKNOWN;
        const texts = parts.map(scalarText);
        return texts.every((t) => t !== undefined) ? texts.join(arg[0]) : UNKNOWN;
      }
      case 'Fn::FindInMap': {
        if (!Array.isArray(arg) || arg.length !== 3) return UNKNOWN;
        const [m, k1, k2] = arg.map((a) => this.value(a));
        if (typeof m !== 'string' || typeof k1 !== 'string' || typeof k2 !== 'string') return UNKNOWN;
        const v = this.template?.Mappings?.[m]?.[k1]?.[k2];
        return v === undefined ? UNKNOWN : (v as Value);
      }
      default:
        return UNKNOWN;
    }
  }

  private ref(name: string): Maybe<Value> {
    const { region, accountId } = this.pseudo;
    switch (name) {
      case 'AWS::Region':
        return region && CONCRETE_REGION.test(region) ? region : UNKNOWN;
      case 'AWS::AccountId':
        return accountId && CONCRETE_ACCOUNT.test(accountId) ? accountId : UNKNOWN;
      case 'AWS::Partition':
        return region && CONCRETE_REGION.test(region) ? partitionOf(region).partition : UNKNOWN;
      case 'AWS::URLSuffix':
        return region && CONCRETE_REGION.test(region) ? partitionOf(region).urlSuffix : UNKNOWN;
      default:
        break;
    }
    const p = this.template?.Parameters?.[name];
    if (!p || typeof p !== 'object' || !('Default' in p)) return UNKNOWN;
    // An SSM parameter type resolves to the stored value, not to the default (which is the parameter name).
    if (typeof p.Type === 'string' && p.Type.startsWith('AWS::SSM::Parameter::Value<')) return UNKNOWN;
    const d = p.Default;
    if (isListParameter(p.Type)) {
      if (Array.isArray(d)) return d.map(String);
      return typeof d === 'string' ? d.split(',') : UNKNOWN;
    }
    if (typeof d === 'string' || typeof d === 'number' || typeof d === 'boolean') return String(d);
    return UNKNOWN;
  }
}

function scalarText(v: Value): string | undefined {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return undefined;
}

/**
 * Logical IDs of the resources whose `Condition` is proven false.
 * A template that is not an object, or has no conditional resources, gives an empty set.
 */
export function inactiveResources(template: unknown, pseudo: PseudoValues = {}): Set<string> {
  const out = new Set<string>();
  const t = template as any;
  const resources = t?.Resources;
  if (!resources || typeof resources !== 'object') return out;
  const ev = new Evaluator(t, pseudo);
  for (const [id, r] of Object.entries<any>(resources)) {
    const name = r?.Condition;
    if (typeof name === 'string' && ev.condition(name) === false) out.add(id);
  }
  return out;
}

/** The same, reading the template from disk. Unreadable or non-JSON templates give an empty set. */
export function inactiveResourcesInFile(templatePath: string, pseudo: PseudoValues = {}): Set<string> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs') as typeof import('fs');
    return inactiveResources(JSON.parse(fs.readFileSync(templatePath, 'utf8')), pseudo);
  } catch {
    return new Set();
  }
}
