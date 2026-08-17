import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';

export default function FindingEvidence({ evidence }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const jsonStr = evidence
    ? typeof evidence === 'string'
      ? evidence
      : JSON.stringify(evidence, null, 2)
    : '{}';

  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="evidence-container">
      <div
        className="evidence-top"
        style={{ cursor: 'pointer' }}
        onClick={() => setOpen(!open)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <span>Scanner Evidence Payload</span>
        </div>
        <button
          className="btn btn-secondary"
          onClick={handleCopy}
          style={{ padding: '2px 6px', fontSize: '10px', height: '22px', backgroundColor: '#334155', color: '#ffffff', borderColor: '#475569' }}
        >
          {copied ? <Check size={11} color="#4ade80" /> : <Copy size={11} />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      {open && (
        <pre className="evidence-content">
          {jsonStr}
        </pre>
      )}
    </div>
  );
}
