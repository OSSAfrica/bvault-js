import { useState, useEffect } from 'react'
import {
  encrypt,
  decrypt,
  initWasm,
  encryptSync,
  decryptSync,
} from 'bvault-js'
import './App.css'

type Engine = 'js' | 'wasm'

function EngineToggle({ value, onChange, wasmReady }: { value: Engine; onChange: (e: Engine) => void; wasmReady: boolean }) {
  return (
    <div className="engine-toggle">
      <button className={value === 'js' ? 'active' : ''} onClick={() => onChange('js')}>
        JS
      </button>
      <button className={value === 'wasm' ? 'active' : ''} onClick={() => onChange('wasm')} disabled={!wasmReady}>
        WASM
      </button>
    </div>
  )
}

function App() {
  const [wasmReady, setWasmReady] = useState(false)

  // Lock
  const [lockEngine, setLockEngine] = useState<Engine>('js')
  const [lockMessage, setLockMessage] = useState('')
  const [lockPassword, setLockPassword] = useState('')
  const [locked, setLocked] = useState<{ encryptedData: string; iv: string; salt: string } | null>(null)
  const [lockTime, setLockTime] = useState<number | null>(null)
  const [lockedWith, setLockedWith] = useState<Engine>('js')

  // Unlock
  const [unlockEngine, setUnlockEngine] = useState<Engine>('wasm')
  const [unlockPassword, setUnlockPassword] = useState('')
  const [unlockResult, setUnlockResult] = useState<string | null>(null)
  const [unlockError, setUnlockError] = useState<string | null>(null)
  const [unlockTime, setUnlockTime] = useState<number | null>(null)

  useEffect(() => {
    initWasm().then(() => setWasmReady(true))
  }, [])

  const handleLock = async () => {
    if (!lockMessage || !lockPassword) return
    setLocked(null)
    setUnlockResult(null)
    setUnlockError(null)
    setUnlockPassword('')

    console.log(`--- Lock with ${lockEngine.toUpperCase()} ---`)
    console.log('Message:', lockMessage)

    const start = performance.now()
    let result: { encryptedData: string; iv: string; salt: string }

    if (lockEngine === 'wasm') {
      result = encryptSync(lockMessage, lockPassword)
    } else {
      result = await encrypt(lockMessage, lockPassword)
    }

    const elapsed = performance.now() - start
    console.log('Encrypted:', result)
    console.log(`Time: ${elapsed.toFixed(1)}ms`)

    setLocked(result)
    setLockTime(elapsed)
    setLockedWith(lockEngine)
  }

  const handleUnlock = async () => {
    if (!locked || !unlockPassword) return
    setUnlockResult(null)
    setUnlockError(null)

    console.log(`--- Unlock with ${unlockEngine.toUpperCase()} ---`)
    console.log('Password attempt:', unlockPassword)

    const start = performance.now()

    try {
      let result: string
      if (unlockEngine === 'wasm') {
        result = decryptSync(locked.encryptedData, unlockPassword, locked.iv, locked.salt)
      } else {
        result = await decrypt(locked.encryptedData, unlockPassword, locked.iv, locked.salt)
      }
      const elapsed = performance.now() - start

      console.log('Decrypted:', result)
      console.log(`Time: ${elapsed.toFixed(1)}ms`)

      setUnlockResult(result)
      setUnlockTime(elapsed)
    } catch (e) {
      const elapsed = performance.now() - start
      const msg = e instanceof Error ? e.message : String(e)
      console.error('Decrypt failed:', msg)

      setUnlockError('Wrong password — decryption failed')
      setUnlockTime(elapsed)
    }
  }

  return (
    <div className="container">
      <h1>bvault-js</h1>
      <p className="subtitle">AES-256-GCM encryption — JS and Rust/WASM interop demo</p>

      {/* Step 1: Lock */}
      <div className="card">
        <div className="card-header">
          <h2>1. Lock your message</h2>
          <EngineToggle value={lockEngine} onChange={setLockEngine} wasmReady={wasmReady} />
        </div>
        <textarea
          placeholder="Type your secret message..."
          value={lockMessage}
          onChange={(e) => setLockMessage(e.target.value)}
          rows={3}
        />
        <input
          type="password"
          placeholder="Choose a password"
          value={lockPassword}
          onChange={(e) => setLockPassword(e.target.value)}
        />
        <button className="action-btn lock-btn" onClick={handleLock} disabled={!lockMessage || !lockPassword}>
          Lock with {lockEngine === 'js' ? 'JavaScript' : 'Rust WASM'}
        </button>
      </div>

      {/* Encrypted output */}
      {locked && (
        <div className="card encrypted-card">
          <h2>
            Encrypted Output
            <span className="engine-badge">{lockedWith === 'js' ? 'JS' : 'WASM'}</span>
          </h2>
          {lockTime !== null && <span className="time">{lockTime.toFixed(1)}ms</span>}
          <div className="cipher-text">{locked.encryptedData}</div>
          <div className="meta">
            <span>IV: {locked.iv}</span>
            <span>Salt: {locked.salt}</span>
          </div>
        </div>
      )}

      {/* Step 2: Unlock */}
      {locked && (
        <div className="card">
          <div className="card-header">
            <h2>2. Unlock it</h2>
            <EngineToggle value={unlockEngine} onChange={setUnlockEngine} wasmReady={wasmReady} />
          </div>

          {lockedWith !== unlockEngine && (
            <div className="interop-badge">
              Cross-impl: {lockedWith === 'js' ? 'JS' : 'WASM'} encrypted → {unlockEngine === 'js' ? 'JS' : 'WASM'} decrypt
            </div>
          )}

          <input
            type="password"
            placeholder="Enter password to decrypt"
            value={unlockPassword}
            onChange={(e) => setUnlockPassword(e.target.value)}
          />
          <button className="action-btn unlock-btn" onClick={handleUnlock} disabled={!unlockPassword}>
            Unlock with {unlockEngine === 'js' ? 'JavaScript' : 'Rust WASM'}
          </button>

          {unlockResult !== null && (
            <div className="result success">
              {unlockTime !== null && <span className="time">{unlockTime.toFixed(1)}ms</span>}
              <div className="result-label">Decrypted message:</div>
              <div className="result-value">{unlockResult}</div>
            </div>
          )}

          {unlockError && (
            <div className="result error">
              {unlockTime !== null && <span className="time">{unlockTime.toFixed(1)}ms</span>}
              <div className="result-value">{unlockError}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default App
