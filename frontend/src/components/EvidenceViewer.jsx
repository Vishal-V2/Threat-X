import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';

export default function EvidenceViewer({ evidence }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const jsonString = evidence
    ? typeof evidence === 'string'
      ? evidence
      : JSON.stringify(evidence, null, 2)
    : '{}';

  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="evidence-box">
      <div className="evidence-header" onClick={() => setOpen(!open)}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.82rem', fontWeight: '600' }}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <span>Raw Evidence</span>
        </div>

        <button
          className="btn btn-secondary"
          onClick={handleCopy}
          style={{ padding: '3px 8px', fontSize: '0.72rem' }}
          title="Copy JSON evidence"
        >
          {copied ? <Check size={12} color="#22c55e" /> : <Copy size={12} />}
          <span>{copied ? 'Copied' : 'Copy JSON'}</span>
        </button>
      </div>

      {open && (
        <pre className="evidence-pre">
          {jsonString}
        </pre>
      )}
    </div>
  );
}
