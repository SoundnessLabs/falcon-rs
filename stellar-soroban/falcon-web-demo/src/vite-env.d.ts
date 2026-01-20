/// <reference types="vite/client" />

interface Window {
  Buffer: typeof Buffer
}

interface ImportMetaEnv {
  readonly VITE_STELLAR_SECRET?: string
  readonly VITE_CONTRACT_ID?: string
  readonly VITE_STELLAR_RPC?: string
  readonly VITE_STELLAR_NETWORK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
