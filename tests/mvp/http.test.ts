import assert from "node:assert/strict";
import test from "node:test";

import { createMvpServer } from "../../src/mvp/http.js";

async function withServer(
  fn: (base: string) => Promise<void>,
): Promise<void> {
  const app = createMvpServer();

  await new Promise<void>((resolve, reject) => {
    app.server.listen(
      {
        port: 0,
        host: "127.0.0.1",
      },
      () => {
        resolve();
      },
    );

    app.server.once("error", reject);
  });

  const address = app.server.address();

  if (!address || typeof address === "string") {
    await app.close();
    throw new Error("TEST_SERVER_ADDRESS_UNAVAILABLE");
  }

  const base = `http://127.0.0.1:${address.port}`;

  try {
    await fn(base);
  } finally {
    await app.close();
  }
}

test("MVP health endpoint is available", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/health`,
    );

    assert.equal(response.status, 200);

    const body = await response.json();

    assert.deepEqual(body, {
      service: "GIIA-MVP",
      status: "OK",
      version: "1",
      executionEndpoint: false,
    });
  });
});

test("MVP evaluate returns authoritative non-execution decision", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/trust/evaluate`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          requestId: "http-evaluate-001",
          action: "read",
          resource: "resource-001",
        }),
      },
    );

    assert.equal(response.status, 200);

    const body = await response.json();
    const decision = body.decision;

    assert.equal(
      decision.recordType,
      "GIIA_AUTHORITATIVE_DECISION",
    );
    assert.equal(decision.authoritative, true);
    assert.equal(decision.executionPermitted, false);
    assert.ok(
      ["ALLOW", "DENY", "DEFER"].includes(
        decision.decision,
      ),
    );
    assert.equal(typeof decision.signature, "string");
  });
});

test("MVP rejects caller-controlled security facts", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/trust/evaluate`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          requestId: "http-security-001",
          action: "read",
          resource: "resource-001",
          authorized: true,
        }),
      },
    );

    assert.equal(response.status, 400);
  });
});

test("MVP rejects caller-controlled execution authority", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/trust/evaluate`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          requestId: "http-security-002",
          action: "read",
          resource: "resource-001",
          executionPermitted: true,
        }),
      },
    );

    assert.equal(response.status, 400);
  });
});

test("MVP rejects malformed JSON", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/trust/evaluate`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: "{not-json",
      },
    );

    assert.equal(response.status, 400);
  });
});

test("MVP has no execution endpoint", async () => {
  await withServer(async base => {
    const response = await fetch(
      `${base}/v1/execute`,
      {
        method: "POST",
      },
    );

    assert.equal(response.status, 404);
  });
});
