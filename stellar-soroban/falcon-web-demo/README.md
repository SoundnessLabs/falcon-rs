# Falcon-512 Verifier Demo

Interactive web demo for Falcon-512 post-quantum signature verification on Soroban.

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Features

- **Key Generation**: Generate Falcon-512 keypairs in the browser
- **Message Signing**: Sign messages with post-quantum security
- **On-Chain Verification**: Verify signatures using the deployed Soroban contract

## Configuration

The demo is pre-configured to use:

- **Network**: Stellar Testnet
- **Contract**: `CCVZDNGKWJPRLOXS4CBOJ2HTYNIW4C3244GG2CAA5V7UIYOMTF355QR7`

To change these, edit `src/lib/stellar.ts`.

## Replacing the Logo

Copy your Soundness logo to `public/soundness-logo.svg`.

```bash
cp /path/to/your/logo.svg public/soundness-logo.svg
```

## Test Vectors

The demo includes pre-computed NIST KAT test vectors that are guaranteed to verify correctly on-chain. Use the "Test Vector" option in Step 1 to load these.

## Tech Stack

- React 18 + TypeScript
- Vite (build tool)
- TailwindCSS (styling)
- Framer Motion (animations)
- @stellar/stellar-sdk (Soroban integration)

## Deployment

Build and deploy the `dist/` folder to any static hosting:

```bash
npm run build
# Deploy dist/ to Vercel, Netlify, etc.
```

For Vercel:

```bash
npx vercel --prod
```

## Development

```bash
# Run dev server with hot reload
npm run dev

# Type check
npx tsc --noEmit

# Lint
npm run lint
```

## Future Enhancements

- [ ] Real Falcon WASM module (currently using test vectors)
- [ ] Freighter wallet integration
- [ ] Mainnet support toggle
- [ ] Share verification results
