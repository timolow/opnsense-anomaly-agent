/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE__HOST?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
