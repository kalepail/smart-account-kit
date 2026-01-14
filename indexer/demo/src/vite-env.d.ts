/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_RPC_URL: string;
  readonly VITE_INDEXER_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
