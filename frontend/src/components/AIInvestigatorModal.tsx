import React, { useState } from 'react';
import { 
  Bot, 
  X, 
  Send, 
  Sparkles, 
  ShieldAlert, 
  CheckCircle, 
  Shield, 
  Terminal,
  Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { Incident } from '../types';

interface AIInvestigatorModalProps {
  incident: Incident;
  pcapId: string;
  onClose: () => void;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  recommendations?: string[];
}

export const AIInvestigatorModal: React.FC<AIInvestigatorModalProps> = ({
  incident,
  pcapId,
  onClose,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `Hello Analyst. I have processed the forensic telemetry for **"${incident.title}"** (Risk Index: **${(incident.risk_score ?? 0).toFixed(1)}/100**).\n\nI can analyze attack vectors, reconstruct timelines, identify lateral movement, and generate containment firewall rules. What would you like to investigate?`,
      recommendations: [
        'Analyze full attack chain & MITRE mapping',
        'Verify if database data was exfiltrated',
        'Generate perimeter containment iptables rule',
      ],
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const quickPrompts = [
    '🔍 Analyze full attack chain & MITRE mapping',
    '💾 Check if data was exfiltrated to external IP',
    '🛡️ Generate immediate iptables containment rule',
    '⚠️ Which internal assets were compromised?',
  ];

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: Message = { role: 'user', content: textToSend };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await api.investigateIncident(pcapId, incident.id, textToSend);
      const assistantMsg: Message = {
        role: 'assistant',
        content: res.response,
        recommendations: res.recommendations,
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: '⚠️ Failed to contact AI Investigation service. Please verify backend connectivity.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
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
      <div className="cyber-card" style={{
        maxWidth: '800px',
        width: '100%',
        height: '85vh',
        display: 'flex',
        flexDirection: 'column',
        padding: '0',
        boxShadow: '0 10px 40px rgba(6, 182, 212, 0.25)',
        border: '1px solid var(--border-glow)',
      }}>
        {/* Header */}
        <div style={{
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: '#0a101f',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, rgba(6,182,212,0.3) 0%, rgba(99,102,241,0.4) 100%)',
              border: '1px solid var(--primary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Bot size={22} color="var(--primary)" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontWeight: 700, fontSize: '1.1rem' }}>AI Incident Investigator</span>
                <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                  <Cpu size={10} /> Copilot Active
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Target: <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{incident.title}</span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="btn btn-secondary btn-sm"
            style={{ borderRadius: '50%', width: '32px', height: '32px', padding: 0 }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Message Thread */}
        <div style={{
          flex: 1,
          overflowY: 'auto',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
          background: 'radial-gradient(circle at 50% 10%, rgba(6,182,212,0.03) 0%, transparent 60%)',
        }}>
          {messages.map((m, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                gap: '0.85rem',
                alignItems: 'flex-start',
                flexDirection: m.role === 'user' ? 'row-reverse' : 'row',
              }}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '6px',
                background: m.role === 'user' ? 'var(--bg-elevated)' : 'rgba(6,182,212,0.2)',
                border: `1px solid ${m.role === 'user' ? 'var(--border-color)' : 'var(--primary)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                {m.role === 'user' ? <Terminal size={16} /> : <Bot size={16} color="var(--primary)" />}
              </div>

              <div style={{
                maxWidth: '82%',
                background: m.role === 'user' ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' : '#0a101f',
                border: `1px solid ${m.role === 'user' ? 'transparent' : 'var(--border-color)'}`,
                borderRadius: 'var(--radius-sm)',
                padding: '1rem 1.25rem',
                fontSize: '0.875rem',
                lineHeight: '1.6',
                color: 'var(--text-main)',
                whiteSpace: 'pre-wrap',
              }}>
                {m.content}

                {m.recommendations && m.recommendations.length > 0 && (
                  <div style={{
                    marginTop: '1rem',
                    paddingTop: '0.75rem',
                    borderTop: '1px solid var(--border-color)',
                  }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                      RECOMMENDED INVESTIGATION STEPS:
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {m.recommendations.map((rec, rIdx) => (
                        <div
                          key={rIdx}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            fontSize: '0.8rem',
                            color: 'var(--primary)',
                            cursor: 'pointer',
                          }}
                          onClick={() => handleSend(rec)}
                        >
                          <Sparkles size={12} />
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div style={{ display: 'flex', gap: '0.85rem', alignItems: 'center' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '6px',
                background: 'rgba(6,182,212,0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <Bot size={16} color="var(--primary)" />
              </div>
              <div style={{
                background: '#0a101f',
                padding: '0.75rem 1rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem',
                color: 'var(--text-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}>
                <div className="status-dot online" />
                <span>AI analyzing incident packet evidence & correlating MITRE tactics...</span>
              </div>
            </div>
          )}
        </div>

        {/* Quick Suggestion Chips */}
        <div style={{
          padding: '0.75rem 1.25rem',
          background: '#070b14',
          borderTop: '1px solid var(--border-color)',
          display: 'flex',
          gap: '0.5rem',
          overflowX: 'auto',
        }}>
          {quickPrompts.map((prompt, pIdx) => (
            <button
              key={pIdx}
              onClick={() => handleSend(prompt)}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}
              disabled={loading}
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div style={{
          padding: '1rem 1.25rem',
          background: '#090e1a',
          borderTop: '1px solid var(--border-color)',
          display: 'flex',
          gap: '0.75rem',
        }}>
          <input
            type="text"
            className="input-control"
            placeholder="Ask AI Investigator about this attack (e.g. 'Generate iptables command to drop attacker')..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            disabled={loading}
          />
          <button
            onClick={() => handleSend()}
            className="btn btn-primary"
            disabled={loading || !input.trim()}
          >
            <Send size={16} />
            <span>Ask</span>
          </button>
        </div>
      </div>
    </div>
  );
};
