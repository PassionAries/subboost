export const LOGIC_RULE_TYPES = ["AND", "OR", "NOT"] as const;

export type LogicRuleType = (typeof LOGIC_RULE_TYPES)[number];

export type LogicRulePayloadResult =
  | { ok: true; value: string }
  | { ok: false; error: string };

const logicRuleTypeSet = new Set<string>(LOGIC_RULE_TYPES);
const SUB_RULE_TYPE_RE = /^[A-Z][A-Z0-9-]*$/;
// mihomo rejects these inside logic rules (rules/logic/logic.go payloadToRule).
const UNSUPPORTED_SUB_RULE_TYPES = new Set(["MATCH", "SUB-RULE"]);

export function isLogicRuleType(value: string): value is LogicRuleType {
  return logicRuleTypeSet.has(value);
}

function splitTopLevel(value: string): string[] | null {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of value) {
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (depth < 0) return null;
    if (char === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (depth !== 0) return null;
  parts.push(current.trim());
  return parts;
}

function unwrapParens(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith("(") || !trimmed.endsWith(")")) return null;
  const inner = trimmed.slice(1, -1);
  // "(A),(B)" starts and ends with parens but is not one wrapped group.
  return splitTopLevel(inner) === null ? null : inner;
}

function normalizeSubRule(raw: string): LogicRulePayloadResult {
  const inner = unwrapParens(raw);
  if (inner === null) return { ok: false, error: `子条件需用括号包裹：${raw}` };
  const commaIndex = inner.indexOf(",");
  if (commaIndex < 0) return { ok: false, error: `子条件缺少值：${raw}` };
  const type = inner.slice(0, commaIndex).trim();
  const rest = inner.slice(commaIndex + 1).trim();
  if (!SUB_RULE_TYPE_RE.test(type)) return { ok: false, error: `子条件类型无效：${type || raw}` };
  if (UNSUPPORTED_SUB_RULE_TYPES.has(type)) return { ok: false, error: `逻辑规则不支持子条件类型：${type}` };
  if (isLogicRuleType(type)) {
    const nested = normalizeLogicRulePayload(type, rest);
    return nested.ok ? { ok: true, value: `(${type},${nested.value})` } : nested;
  }
  if (rest.includes("(") || rest.includes(")")) return { ok: false, error: `子条件值不能包含括号：${raw}` };
  const params = rest.split(",").map((part) => part.trim());
  if (!params[0] || params.some((part) => !part)) return { ok: false, error: `子条件值不能为空：${raw}` };
  return { ok: true, value: `(${[type, ...params].join(",")})` };
}

/**
 * Validates a mihomo logic rule payload such as `((DOMAIN,a.com),(NETWORK,UDP))`
 * and returns it with whitespace around tokens removed.
 */
export function normalizeLogicRulePayload(type: LogicRuleType, payload: string): LogicRulePayloadResult {
  const inner = unwrapParens(payload);
  if (inner === null) return { ok: false, error: "逻辑规则内容需形如 ((类型,值),(类型,值))" };
  const rawSubRules = splitTopLevel(inner);
  if (!rawSubRules || rawSubRules.some((part) => !part)) return { ok: false, error: "逻辑规则内容格式错误" };
  if (type === "NOT" && rawSubRules.length !== 1) return { ok: false, error: "NOT 规则只能包含 1 个子条件" };
  if (type !== "NOT" && rawSubRules.length < 2) return { ok: false, error: `${type} 规则至少需要 2 个子条件` };

  const subRules: string[] = [];
  for (const raw of rawSubRules) {
    const normalized = normalizeSubRule(raw);
    if (!normalized.ok) return normalized;
    subRules.push(normalized.value);
  }
  return { ok: true, value: `(${subRules.join(",")})` };
}

/** Single validation entry for a custom rule value, shared by UI input, batch import and persisted configs. */
export function normalizeCustomRuleValue(type: string, value: string): LogicRulePayloadResult {
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, error: "规则值不能为空" };
  return isLogicRuleType(type) ? normalizeLogicRulePayload(type, trimmed) : { ok: true, value: trimmed };
}
