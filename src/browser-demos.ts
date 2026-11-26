/**
 * Real in-browser `@lionlang/core@0.19.0` engine bundle powering the live
 * interactive demos on Lion Gate, Lion Dossier, Lion Fabric, and the standalone
 * client-side Ed25519 ProofEnvelope Verifier.
 */
import { run } from "@lionlang/core/evaluation/evaluate";
import { encodeWire } from "@lionlang/core/evaluation/wire";
import { LogicDatabase } from "@lionlang/core/logic/database";
import {
  createProofEnvelope,
  type EnvelopeVerification,
  generateSigningKeyPair,
  type ProofEnvelope,
  type SigningKeyPair,
  verifyProofEnvelope,
} from "@lionlang/core/logic/envelope";
import { safeStdlib } from "@lionlang/core/modules";
import { Effect } from "effect";

let cachedKeyPair: Promise<SigningKeyPair> | undefined;
const getDemoKeyPair = () => {
  cachedKeyPair ??= Effect.runPromise(generateSigningKeyPair());
  return cachedKeyPair;
};

const newDb = () => new LogicDatabase();

const runLion = async (program: unknown, db: LogicDatabase = newDb()) =>
  Effect.runPromise(run(program as never, safeStdlib, { database: db }));

// =========================================================================
// 1. LION GATE LIVE DEMO
// =========================================================================
const GATE_POLICY: unknown[] = [
  "begin",
  ["relation", "customer", ["id", "tier", "kyc_verified", "balance"], { key: ["id"] }],
  ["relation", "tier_limit", ["tier", "max_auto_refund"], { key: ["tier"] }],
  ["relation", "proposed_refund", ["req_id", "cust_id", "amount"], { key: ["req_id"] }],
  ["relation", "approved_by_human", ["req_id"]],
  ["relation", "refund_allowed", ["req_id"]],
  ["relation", "refund_denied_reason", ["req_id", "reason"]],
  [
    "fact",
    ["tier_limit", "standard", 100],
    ["tier_limit", "pro", 500],
    ["customer", "cust_alice", "pro", true, 1200],
    ["customer", "cust_bob", "standard", false, 80],
  ],
  [
    "define",
    "apply_refund",
    [
      "lambda",
      ["balance", "amount"],
      [
        "cond",
        [["number/lessThanOrEqualTo", "amount", "balance"], ["number/subtract", "balance", "amount"]],
        ["else", "balance"],
      ],
    ],
    { persist: true },
  ],
  [
    "define",
    "buggy_refund",
    ["lambda", ["balance", "amount"], ["number/subtract", "balance", "amount"]],
    { persist: true },
  ],
  [
    "rule",
    ["refund_denied_reason", "?req", "kyc_unverified"],
    ["proposed_refund", "?req", "?c", "?_"],
    ["customer", "?c", "?_", false, "?_"],
  ],
  [
    "rule",
    ["refund_denied_reason", "?req", "invalid_amount"],
    ["proposed_refund", "?req", "?_", "?amt"],
    ["number/lessThanOrEqualTo", "?amt", 0],
  ],
  [
    "rule",
    ["refund_denied_reason", "?req", "exceeds_balance"],
    ["proposed_refund", "?req", "?c", "?amt"],
    ["customer", "?c", "?_", "?_", "?bal"],
    ["number/greaterThan", "?amt", "?bal"],
  ],
  [
    "rule",
    ["refund_denied_reason", "?req", "needs_human_approval"],
    ["proposed_refund", "?req", "?c", "?amt"],
    ["customer", "?c", "?tier", true, "?_"],
    ["tier_limit", "?tier", "?cap"],
    ["number/greaterThan", "?amt", "?cap"],
    ["not", ["approved_by_human", "?req"]],
  ],
  [
    "rule",
    ["refund_allowed", "?req"],
    ["proposed_refund", "?req", "?c", "?amt"],
    ["customer", "?c", "?_", true, "?bal"],
    ["number/greaterThan", "?amt", 0],
    ["number/lessThanOrEqualTo", "?amt", "?bal"],
    ["not", ["refund_denied_reason", "?req", "?_"]],
  ],
];

export interface GateEvalResult {
  readonly allowed: boolean;
  readonly deniedReasons: string[];
  readonly envelope: ProofEnvelope;
  readonly latencyMs: number;
  readonly verified: boolean;
}

export const demoGateEvaluate = async (opts: {
  readonly amount: number;
  readonly approvedByHuman: boolean;
  readonly customerId: "cust_alice" | "cust_bob";
  readonly reqId: string;
}): Promise<GateEvalResult> => {
  const db = newDb();
  await runLion(GATE_POLICY, db);
  const t0 = performance.now();
  const facts: unknown[] = [
    ["proposed_refund", opts.reqId, opts.customerId, opts.amount],
  ];
  if (opts.approvedByHuman) {
    facts.push(["approved_by_human", opts.reqId]);
  }
  const query = [
    "assuming",
    ["fact", ...facts],
    [
      "array/make",
      ["find", true, ["refund_allowed", opts.reqId]],
      ["find", "?r", ["refund_denied_reason", opts.reqId, "?r"]],
    ],
  ];
  const [allowedRows, reasonRows] = (await runLion(query, db)) as [
    unknown[],
    string[],
  ];

  const allowed = allowedRows.length > 0;
  const kp = await getDemoKeyPair();
  const envelope = await Effect.runPromise(
    createProofEnvelope({
      database: db,
      issuer: "lion-gate-demo",
      keyPair: kp,
      query,
      result: {
        allowed,
        amount: opts.amount,
        approvedByHuman: opts.approvedByHuman,
        customerId: opts.customerId,
        deniedReasons: reasonRows,
        reqId: opts.reqId,
      },
    })
  );
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  const ver = await Effect.runPromise(
    verifyProofEnvelope(envelope, kp.publicKeyJwk)
  );

  return {
    allowed,
    deniedReasons: reasonRows,
    envelope,
    latencyMs,
    verified: ver.valid,
  };
};

export const demoGateProve = async (kind: "safe" | "buggy") => {
  const db = newDb();
  await runLion(GATE_POLICY, db);
  const fnName = kind === "safe" ? "apply_refund" : "buggy_refund";
  const query = [
    "proof/prove",
    [
      "not",
      [
        "exists",
        ["?bal", "?amt"],
        [
          "and",
          ["schema/fits?", "?bal", "value/integer?"],
          ["schema/fits?", "?amt", "value/integer?"],
          ["number/greaterThanOrEqualTo", "?bal", 0],
          ["number/greaterThan", "?amt", 0],
          ["number/lessThan", [fnName, "?bal", "?amt"], 0],
        ],
      ],
    ],
  ];
  const t0 = performance.now();
  const rawResult = (await runLion(query, db)) as {
    counterexample?: unknown;
    proved: boolean;
    witness?: unknown;
  };
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  const kp = await getDemoKeyPair();
  const envelope = await Effect.runPromise(
    createProofEnvelope({
      database: db,
      issuer: "lion-gate-demo",
      keyPair: kp,
      proof: rawResult.proved ? rawResult : undefined,
      query,
      result: { fnName, kind, proved: rawResult.proved },
    })
  );
  const ver = await Effect.runPromise(
    verifyProofEnvelope(envelope, kp.publicKeyJwk)
  );
  return {
    envelope,
    latencyMs,
    result: encodeWire(rawResult) as {
      counterexample?: unknown;
      proved: boolean;
    },
    verified: ver.valid && (ver.proofValid === null || ver.proofValid),
  };
};

// =========================================================================
// 2. LION DOSSIER LIVE DEMO
// =========================================================================
export const demoDossierCheckQuote = async (opts: {
  readonly quote: string;
  readonly sourceText: string;
  readonly value: number;
}) => {
  const t0 = performance.now();
  const check = (await runLion([
    "begin",
    ["define", "contains", ["string/includes", opts.sourceText, opts.quote]],
    ["define", "nums", ["string/numbers", opts.quote]],
    {
      extractedNumbers: "nums",
      quoteInSource: "contains",
      valueFoundInQuote: [
        "array/some?",
        "nums",
        ["lambda", ["n"], ["value/equals?", "n", opts.value]],
      ],
    },
  ])) as {
    extractedNumbers: unknown[];
    quoteInSource: boolean;
    valueFoundInQuote: boolean;
  };
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  const accepted = check.quoteInSource && check.valueFoundInQuote;
  return {
    accepted,
    extractedNumbers: encodeWire(check.extractedNumbers),
    httpStatus: accepted ? 201 : 422,
    latencyMs,
    quoteInSource: check.quoteInSource,
    reason: !check.quoteInSource
      ? "HTTP 422: Quote is not a verbatim substring of the source document."
      : !check.valueFoundInQuote
        ? `HTTP 422: Claimed number ${opts.value} does not match numbers extracted from quote (${JSON.stringify(encodeWire(check.extractedNumbers))}).`
        : "HTTP 201: Grounded claim verified verbatim + numeric match.",
    valueFoundInQuote: check.valueFoundInQuote,
  };
};

export const demoDossierBoundsAndSign = async (opts: {
  readonly cogs: number;
  readonly revenue: number;
}) => {
  const db = newDb();
  const query = [
    "proof/bounds",
    ["number/divide", ["number/subtract", "?r", "?c"], "?r"],
    [
      "and",
      ["schema/fits?", "?r", "value/number?"],
      ["schema/fits?", "?c", "value/number?"],
      ["number/greaterThanOrEqualTo", "?r", opts.revenue - 2],
      ["number/lessThanOrEqualTo", "?r", opts.revenue + 2],
      ["number/greaterThanOrEqualTo", "?c", opts.cogs - 2],
      ["number/lessThanOrEqualTo", "?c", opts.cogs + 2],
    ],
  ];
  const t0 = performance.now();
  const rawBounds = await runLion(query, db);
  const kp = await getDemoKeyPair();
  const envelope = await Effect.runPromise(
    createProofEnvelope({
      database: db,
      issuer: "lion-dossier-demo",
      keyPair: kp,
      proof: rawBounds,
      query,
      result: {
        cogsRange: [opts.cogs - 2, opts.cogs + 2],
        metric: "gross_margin",
        revenueRange: [opts.revenue - 2, opts.revenue + 2],
      },
    })
  );
  const verification = await Effect.runPromise(
    verifyProofEnvelope(envelope, kp.publicKeyJwk)
  );
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  return {
    bounds: encodeWire(rawBounds),
    envelope,
    latencyMs,
    verification,
  };
};

// =========================================================================
// 3. LION FABRIC LIVE DEMO
// =========================================================================
export const demoFabricStaleness = async (opts: {
  readonly editedContent: string;
  readonly initialContent: string;
}) => {
  const t0 = performance.now();
  const db = newDb();
  const res = (await runLion(
    [
      "begin",
      ["relation", "artifact", ["path", "hash"], { key: ["path"] }],
      [
        "relation",
        "observation",
        ["id", "question", "value", "path", "observed_hash"],
        { key: ["id"] },
      ],
      ["relation", "stale_observation", ["id", "question"]],
      ["relation", "fresh_observation", ["id", "question"]],
      [
        "rule",
        ["stale_observation", "?id", "?q"],
        ["observation", "?id", "?q", "?_", "?path", "?old"],
        ["artifact", "?path", "?cur"],
        ["not", ["value/equals?", "?old", "?cur"]],
      ],
      [
        "rule",
        ["fresh_observation", "?id", "?q"],
        ["observation", "?id", "?q", "?_", "?path", "?old"],
        ["artifact", "?path", "?old"],
      ],
      ["define", "h1", ["string/sha256", opts.initialContent]],
      ["define", "h2", ["string/sha256", opts.editedContent]],
      [
        "fact",
        ["artifact", "services/checkout.ts", "h1"],
        ["observation", "obs_1", "pool_exhausted", true, "services/checkout.ts", "h1"],
        ["observation", "obs_2", "dns_timeout", false, "services/checkout.ts", "h1"],
      ],
      ["define", "beforeFresh", ["find", "?id", ["fresh_observation", "?id", "?_"]]],
      [
        "define",
        "blastRadius",
        [
          "assuming",
          ["fact", ["artifact", "services/checkout.ts", "h2"]],
          ["find", "?id", ["stale_observation", "?id", "?_"]],
        ],
      ],
      {
        beforeFresh: "beforeFresh",
        editedHash: "h2",
        initialHash: "h1",
        unchanged: ["value/equals?", "h1", "h2"],
        wouldBecomeStale: "blastRadius",
      },
    ],
    db
  )) as {
    beforeFresh: string[];
    editedHash: string;
    initialHash: string;
    unchanged: boolean;
    wouldBecomeStale: string[];
  };
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;
  return { ...res, latencyMs };
};

// =========================================================================
// 4. STANDALONE CLIENT-SIDE PROOF ENVELOPE VERIFIER
// =========================================================================
export const demoVerifyEnvelopeJson = async (
  rawJson: string
): Promise<EnvelopeVerification> => {
  const envelope = JSON.parse(rawJson) as ProofEnvelope;
  return Effect.runPromise(verifyProofEnvelope(envelope, envelope.publicKeyJwk));
};

declare global {
  interface Window {
    LionDemos?: {
      demoDossierBoundsAndSign: typeof demoDossierBoundsAndSign;
      demoDossierCheckQuote: typeof demoDossierCheckQuote;
      demoFabricStaleness: typeof demoFabricStaleness;
      demoGateEvaluate: typeof demoGateEvaluate;
      demoGateProve: typeof demoGateProve;
      demoVerifyEnvelopeJson: typeof demoVerifyEnvelopeJson;
    };
  }
}

if (typeof window !== "undefined") {
  window.LionDemos = {
    demoDossierBoundsAndSign,
    demoDossierCheckQuote,
    demoFabricStaleness,
    demoGateEvaluate,
    demoGateProve,
    demoVerifyEnvelopeJson,
  };
}
