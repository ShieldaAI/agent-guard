import React, { useEffect, useRef, useState } from 'react';
import { displayValue } from '../labels.mjs';
import { shortIdentifier } from '../view-model.mjs';

/** Copies text with the Clipboard API, or through a temporary selection where that is not permitted. */
async function copyText(value) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Fall through to the selection-based copy.
  }
  try {
    const area = document.createElement('textarea');
    area.value = value;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    const copied = document.execCommand('copy');
    area.remove();
    return copied;
  } catch {
    return false;
  }
}
function CopyButton({ value }) {
  const [message, setMessage] = useState('');
  const timer = useRef(null),
    mounted = useRef(true);
  useEffect(
    () => () => {
      mounted.current = false;
      clearTimeout(timer.current);
    },
    [],
  );
  async function copy() {
    const copied = await copyText(value);
    if (!mounted.current) return;
    setMessage(copied ? 'Copied' : 'Copy failed');
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setMessage(''), 2000);
  }
  return (
    <>
      <button type="button" className="copy-button" aria-label="Copy full identifier" onClick={copy}>
        Copy
      </button>
      <span className="copy-status" role="status">
        {message}
      </span>
    </>
  );
}

/**
 * An identifier as evidence shows it. A short value is plain text. A long one (an opaque
 * reference, a source id, an ARN) is shortened to its first ten and last six characters: the
 * full value is in the tooltip, opens in place, and can be copied. `name` leads when the item
 * has a display name of its own. A list is shown item by item.
 */
export function Identifier({ value, name = null }) {
  if (Array.isArray(value)) {
    if (!value.some(item => shortIdentifier(item) !== null))
      return <span className="full-reference">{displayValue(value)}</span>;
    return (
      <span className="identifier-list">
        {value.map((item, index) => (
          <Identifier key={`${index}:${item}`} value={item} />
        ))}
      </span>
    );
  }
  const short = shortIdentifier(value);
  const label =
    typeof name === 'string' && name && name !== value ? <strong className="identifier-name">{name}</strong> : null;
  if (short === null)
    return (
      <>
        {label}
        <span className="full-reference">{displayValue(value)}</span>
      </>
    );
  return (
    <>
      {label}
      <span className="identifier">
        <details className="identifier-details">
          <summary title={value}>{short}</summary>
          <span className="full-reference">{value}</span>
        </details>
        <CopyButton value={value} />
      </span>
    </>
  );
}
