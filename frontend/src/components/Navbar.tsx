import React, { useState } from 'react';
import { 
  Shield, 
  UserCheck, 
  LogOut, 
  RefreshCw, 
  Key, 
  Sparkles, 
  Check, 
  X,
  Bot
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const { user, systemStatus, logout, loginDemo } = useAuth();
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [apiKey, setApiKey] = useState(localStorage.getItem('aegisnet_openai_key') || '');
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSaveKey = () => {
    localStorage.setItem('aegisnet_openai_key', apiKey.trim());
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      setShowKeyModal(false);
    }, 1200);
  };

  const hasCustomKey = !!apiKey.trim();

  return (
    <>
      <header style={{
        height: '64px',
        background: '#090e1a',
        borderBottom: '1px solid var(--border-color)',
        padding: '0 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, rgba(6,182,212,0.2) 0%, rgba(2,132,199,0.4) 100%)',
            border: '1px solid var(--primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6,182,212,0.3)'
          }}>
            <Shield size={22} color="var(--primary)" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.2rem', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>Aegis</span>
              <span style={{ color: 'var(--primary)' }}>Net</span>
              <span style={{ fontSize: '0.65rem', background: '#1e293b', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#94a3b8' }}>v1.0</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
              AI-Assisted Network Defense & Threat Analysis
            </div>
          </div>
        </div>

        {/* Center Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {/* Backend Status */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            background: '#0d1527',
            padding: '0.35rem 0.85rem',
            borderRadius: '9999px',
            border: '1px solid var(--border-color)',
            fontSize: '0.8rem'
          }}>
            <div className={`status-dot ${systemStatus === 'connected' ? 'online' : 'demo'}`} />
            <span style={{ color: 'var(--text-muted)' }}>Backend:</span>
            <span style={{ fontWeight: 600, color: systemStatus === 'connected' ? 'var(--success)' : 'var(--primary)' }}>
              {systemStatus === 'connected' ? 'FastAPI Port 8001' : 'Simulation Engine'}
            </span>
          </div>

          {/* AI Status Button */}
          <button
            onClick={() => setShowKeyModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: hasCustomKey ? 'rgba(16, 185, 129, 0.1)' : 'rgba(6, 182, 212, 0.08)',
              border: `1px solid ${hasCustomKey ? 'rgba(16, 185, 129, 0.4)' : 'var(--border-color)'}`,
              padding: '0.35rem 0.85rem',
              borderRadius: '9999px',
              fontSize: '0.8rem',
              color: hasCustomKey ? 'var(--success)' : 'var(--primary)',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
            title="Configure OpenAI API Key"
          >
            <Bot size={14} />
            <span style={{ fontWeight: 600 }}>
              {hasCustomKey ? 'OpenAI: GPT-4o' : 'AI Copilot: Local Defense AI'}
            </span>
          </button>
        </div>

        {/* Right User Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          {user ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{user.full_name || user.username}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{user.email}</div>
                </div>
                <span className={`badge ${user.role === 'ADMIN' ? 'badge-critical' : user.role === 'ANALYST' ? 'badge-cyan' : 'badge-low'}`}>
                  {user.role}
                </span>
              </div>

              <button
                onClick={() => loginDemo(user.role === 'ADMIN' ? 'ANALYST' : 'ADMIN')}
                className="btn btn-secondary btn-sm"
                title="Toggle role permissions"
              >
                <RefreshCw size={12} />
                Switch to {user.role === 'ADMIN' ? 'Analyst' : 'Admin'}
              </button>

              <button
                onClick={() => {
                  logout();
                  window.location.href = '/login';
                }}
                className="btn btn-secondary btn-sm"
                title="Sign Out to Login Portal"
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <LogOut size={14} />
                <span>Logout</span>
              </button>
            </>
          ) : (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <a 
                href="/login" 
                className="btn btn-primary btn-sm"
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', textDecoration: 'none' }}
              >
                <UserCheck size={14} />
                <span>Login Portal</span>
              </a>
            </div>
          )}
        </div>
      </header>

      {/* OpenAI Settings Modal */}
      {showKeyModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          background: 'rgba(5, 8, 16, 0.75)',
          backdropFilter: 'blur(6px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.5rem',
        }}>
          <div className="cyber-card" style={{ maxWidth: '480px', width: '100%', padding: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Key size={20} color="var(--primary)" />
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>OpenAI API Configuration</h3>
              </div>
              <button
                onClick={() => setShowKeyModal(false)}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '50%', width: '28px', height: '28px', padding: 0 }}
              >
                <X size={14} />
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
              AegisNet supports <strong>OpenAI GPT-4o</strong> for automated threat intelligence and incident investigation. If no key is set, the built-in <strong>Autonomous Cyber Heuristic Copilot</strong> analyzes MITRE ATT&CK tactics offline.
            </p>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                OpenAI API Key (sk-...)
              </label>
              <input
                type="password"
                className="input-control font-mono"
                placeholder="sk-proj-..."
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.35rem', display: 'block' }}>
                You can also configure this directly in the <code>.env</code> file.
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                onClick={() => {
                  setApiKey('');
                  localStorage.removeItem('aegisnet_openai_key');
                  setShowKeyModal(false);
                }}
                className="btn btn-secondary btn-sm"
              >
                Reset to Local AI
              </button>

              <button
                onClick={handleSaveKey}
                className="btn btn-primary btn-sm"
              >
                {savedSuccess ? (
                  <>
                    <Check size={14} /> Saved!
                  </>
                ) : (
                  <>
                    <Sparkles size={14} /> Save Configuration
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
