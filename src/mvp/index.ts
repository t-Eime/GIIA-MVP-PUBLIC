import { createMvpServer } from "./http.js";

const port = Number(process.env.GIIA_MVP_PORT ?? "8787");
const host = process.env.GIIA_MVP_HOST ?? "127.0.0.1";

const { server, close } = createMvpServer({
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

server.listen(port, host, () => {
  console.log(
    `GIIA MVP listening on http://${host}:${port}`,
  );
});

const shutdown = async () => {
  await close();
  process.exit(0);
};

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
