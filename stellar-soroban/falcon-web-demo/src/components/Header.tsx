import { motion } from 'framer-motion'
import { Github, ExternalLink } from 'lucide-react'
import { CONTRACT_ID, NETWORK } from '@/lib/stellar'

export function Header() {
  const explorerNetwork = NETWORK === 'mainnet' ? 'public' : 'testnet'
  const contractExplorerUrl = `https://stellar.expert/explorer/${explorerNetwork}/contract/${CONTRACT_ID}`
  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full py-6 px-4 sm:px-6 lg:px-8"
    >
      <div className="max-w-5xl mx-auto flex items-center justify-between">
        {/* Logo and Title */}
        <div className="flex items-center gap-4">
          <a href="https://soundness.xyz" target="_blank" rel="noopener noreferrer">
            <img
              src="/soundness_logo.png"
              alt="Soundness"
              className="h-10 w-10"
            />
          </a>
          <div className="hidden sm:block">
            <h1 className="text-xl font-bold text-white">
              Falcon-512 Verifier
            </h1>
            <p className="text-sm text-muted-foreground">
              Post-Quantum Signatures on Soroban
            </p>
          </div>
        </div>

        {/* Links */}
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/soundness/falcon-rust"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors"
          >
            <Github size={20} />
            <span className="hidden sm:inline">GitHub</span>
          </a>
          <a
            href={contractExplorerUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors"
          >
            <ExternalLink size={20} />
            <span className="hidden sm:inline">Contract</span>
          </a>
        </div>
      </div>
    </motion.header>
  )
}
