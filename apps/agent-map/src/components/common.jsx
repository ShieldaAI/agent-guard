import React from 'react';

const ICON_PATHS = {
  search: 'M21 21l-5.5-5.5M18 10.5a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0',
  network: 'M6 5h12M6 19h12M5 6v12M19 6v12M7 7l10 10M17 7L7 17',
  layers: 'M12 3l10 6-10 6L2 9l10-6M2 14l10 6 10-6',
  clock: 'M12 8v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  refresh: 'M20 7V2l-3 3a9 9 0 1 0 3 13M20 2h-5',
  close: 'M6 6l12 12M18 6L6 18',
  lock: 'M6 10h12v11H6V10M8 10V6a4 4 0 0 1 8 0v4',
  fit: 'M8 3H3v5M16 3h5v5M21 16v5h-5M8 21H3v-5',
  shield: 'M12 2l8 3v6c0 5-4 9-8 11-4-2-8-6-8-11V5l8-3M8 12l3 3 5-6',
  logout: 'M9 4H4v16h5M10 12h11M16 7l5 5-5 5',
};
export function Icon({ name, size = 18 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={ICON_PATHS[name] ?? ICON_PATHS.network} />
    </svg>
  );
}
export function Status({ children, tone = 'neutral' }) {
  return (
    <span className={`status ${tone}`}>
      <span className="status-dot" />
      {children}
    </span>
  );
}
/** A block notice; an error is announced. */
export function Notice({ children, error = false }) {
  return (
    <div className={`notice ${error ? 'error' : ''}`} role={error ? 'alert' : undefined}>
      {children}
    </div>
  );
}
/** A one-paragraph notice inside a card. */
export function Note({ children, error = false }) {
  return (
    <p className={`notice ${error ? 'error' : ''}`} role={error ? 'alert' : undefined}>
      {children}
    </p>
  );
}
export function Empty({ title, children }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name="network" size={30} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
