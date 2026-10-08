import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

import { createMvpComposition, type MvpCompositionOptions } from "./composition.js";
import type {
  MvpDecisionRecord,
  MvpHealthResponse,
} from "./types.js";
import { validateEvaluateRequest } from "./validation.js";
import { verifyDecisionRecord } from "./verification.js";

const MAX_BODY_BYTES = 64 * 1024;

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = JSON.stringify(body);

  response.statusCode = status;
  response.setHeader("Content-Type", "application/json");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.end(payload);
}

async function readBody(
  request: IncomingMessage,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk);

    size += buffer.length;

    if (size > MAX_BODY_BYTES) {
      throw new Error("REQUEST_BODY_TOO_LARGE");
    }

    chunks.push(buffer);
  }

  if (chunks.length === 0) {
    throw new Error("EMPTY_REQUEST_BODY");
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("INVALID_JSON");
  }
}

function routeNotFound(response: ServerResponse): void {
  sendJson(response, 404, {
    error: "NOT_FOUND",
  });
}

export function createMvpServer(
  options: MvpCompositionOptions = {},
): {
  server: Server;
  close: () => Promise<void>;
} {
  const composition = createMvpComposition(options);

  const server = createServer(async (request, response) => {
    try {
      const method = request.method ?? "";
      const url = new URL(
        request.url ?? "/",
        "http://127.0.0.1",
      );

      if (method === "GET" && url.pathname === "/v1/health") {
        const body: MvpHealthResponse = {
          service: "GIIA-MVP",
          status: "OK",
          version: "1",
          executionEndpoint: false,
        };

        sendJson(response, 200, body);
        return;
      }

      if (
        method === "POST" &&
        url.pathname === "/v1/trust/evaluate"
      ) {
        const body = await readBody(request);
        const input = validateEvaluateRequest(body);

        const result = composition.evaluate(input);

        const record =
          composition.createDecisionRecord(
            result,
            input.requestId,
            input.action,
            input.resource,
            input.requestedAt,
          );

        sendJson(response, 200, {
          decision: record,
        });

        return;
      }

      if (
        method === "POST" &&
        url.pathname === "/v1/trust/verify"
      ) {
        const body = await readBody(request);

        if (
          !body ||
          typeof body !== "object" ||
          Array.isArray(body)
        ) {
          throw new Error("INVALID_VERIFICATION_BODY");
        }

        const input = body as Record<string, unknown>;

        if (!Object.prototype.hasOwnProperty.call(
          input,
          "decision",
        )) {
          throw new Error("MISSING_DECISION_RECORD");
        }

        const result = verifyDecisionRecord(
          input.decision,
        );

        sendJson(
          response,
          result.valid ? 200 : 422,
          result,
        );

        return;
      }

      routeNotFound(response);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "REQUEST_REJECTED";

      const status =
        message === "REQUEST_BODY_TOO_LARGE"
          ? 413
          : message.startsWith("INVALID_") ||
              message.startsWith("SECURITY_") ||
              message.startsWith("REQUESTED_") ||
              message.startsWith("EXECUTION_")
            ? 400
            : 400;

      sendJson(response, status, {
        error: message,
      });
    }
  });

  return {
    server,
    async close() {
      composition.close();

      if (!server.listening) {
        return;
      }

      await new Promise<void>((resolve, reject) => {
        server.close(error => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    },
  };
}


export function startMvpServer(
  port = Number(process.env.GIIA_MVP_PORT ?? "8787"),
  host = process.env.GIIA_MVP_HOST ?? "127.0.0.1",
): {
  server: Server;
  close: () => Promise<void>;
} {
  const app = createMvpServer({
    durableBootstrap: true,
    bootstrapPaths: {
      keystorePath:
        process.env.GIIA_MVP_KEYSTORE_PATH ??
        "runtime-data/mvp-bootstrap.keystore",
      trustRegistryPath:
        process.env.GIIA_MVP_TRUST_REGISTRY_PATH ??
        "runtime-data/mvp-trust.db",
    },
  });

  app.server.listen(
    {
      port,
      host,
    },
    () => {
      console.log(
        `GIIA MVP listening on http://${host}:${port}`,
      );
    },
  );

  return app;
}
