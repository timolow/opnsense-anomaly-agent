/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PFELK_HOST?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
