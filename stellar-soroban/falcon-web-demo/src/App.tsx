import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Toaster } from 'sonner'
import { Header } from './components/Header'
import { Footer } from './components/Footer'
import { StepCard } from './components/StepCard'
import { KeyGenerator } from './components/KeyGenerator'
import { MessageSigner } from './components/MessageSigner'
import { OnChainVerifier } from './components/OnChainVerifier'
import { initFalcon, type FalconKeyPair } from './lib/falcon'

function App() {
  const [isInitialized, setIsInitialized] = useState(false)
  const [activeStep, setActiveStep] = useState(1)

  // State from each step
  const [keys, setKeys] = useState<FalconKeyPair | null>(null)
  const [seed, setSeed] = useState<Uint8Array | null>(null)
  const [message, setMessage] = useState<Uint8Array | null>(null)
  const [signature, setSignature] = useState<Uint8Array | null>(null)

  // Initialize Falcon module
  useEffect(() => {
    initFalcon().then(() => {
      setIsInitialized(true)
    })
  }, [])

  const handleKeysGenerated = (newKeys: FalconKeyPair, newSeed: Uint8Array) => {
    setKeys(newKeys)
    setSeed(newSeed)
    setMessage(null)
    setSignature(null)
    setActiveStep(2)
  }

  const handleMessageSigned = (msg: Uint8Array, sig: Uint8Array) => {
    setMessage(msg)
    setSignature(sig)
    setActiveStep(3)
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#171717',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#fff',
          },
        }}
      />

      {/* Background gradient */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-soundness-blue/20 rounded-full blur-[128px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-[128px]" />
      </div>

      <Header />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Hero Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-12"
          >
            <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
              Post-Quantum Signatures
              <br />
              <span className="text-gradient-blue">on Stellar</span>
            </h1>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Generate Falcon-512 keys, sign messages in your browser, and verify
              signatures on-chain using Soroban smart contracts.
            </p>
          </motion.div>

          {/* Loading State */}
          {!isInitialized && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center py-12"
            >
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                className="w-12 h-12 border-4 border-soundness-blue/30 border-t-soundness-blue rounded-full mx-auto mb-4"
              />
              <p className="text-muted-foreground">Initializing Falcon module...</p>
            </motion.div>
          )}

          {/* Steps */}
          {isInitialized && (
            <>
              {/* Step 1: Key Generation */}
              <StepCard
                stepNumber={1}
                title="Generate Keypair"
                description="Create a Falcon-512 public/private keypair from a seed"
                isActive={activeStep === 1}
                isComplete={keys !== null}
              >
                <KeyGenerator
                  onKeysGenerated={handleKeysGenerated}
                  isActive={activeStep === 1}
                />
              </StepCard>

              {/* Step 2: Sign Message */}
              <StepCard
                stepNumber={2}
                title="Sign Message"
                description="Sign a message using your Falcon-512 private key"
                isActive={activeStep === 2}
                isComplete={signature !== null}
              >
                <MessageSigner
                  keys={keys}
                  seed={seed}
                  onMessageSigned={handleMessageSigned}
                  isActive={activeStep === 2}
                />
              </StepCard>

              {/* Step 3: Verify On-Chain */}
              <StepCard
                stepNumber={3}
                title="Verify Signature"
                description="Verify the signature locally or on-chain via Soroban"
                isActive={activeStep === 3}
                isComplete={false}
              >
                <OnChainVerifier
                  keys={keys}
                  seed={seed}
                  message={message}
                  signature={signature}
                  isActive={activeStep === 3}
                />
              </StepCard>
            </>
          )}

          {/* Info Section */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-12"
          >
            <div className="p-4 bg-card/30 rounded-xl border border-white/5 text-center">
              <div className="text-3xl font-bold text-soundness-blue mb-1">512</div>
              <div className="text-sm text-muted-foreground">Polynomial Degree</div>
            </div>
            <div className="p-4 bg-card/30 rounded-xl border border-white/5 text-center">
              <div className="text-3xl font-bold text-soundness-blue mb-1">128-bit</div>
              <div className="text-sm text-muted-foreground">Post-Quantum Security</div>
            </div>
            <div className="p-4 bg-card/30 rounded-xl border border-white/5 text-center">
              <div className="text-3xl font-bold text-soundness-blue mb-1">~400k</div>
              <div className="text-sm text-muted-foreground">CPU Instructions</div>
            </div>
          </motion.div>
        </div>
      </main>

      <Footer />
    </div>
  )
}

export default App
