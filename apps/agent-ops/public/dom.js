// Small DOM helpers. Text always enters the page as text nodes, never as markup.
import { stateLabel } from './text.js';

export function node(tag, attributes = {}, ...children) {
  const item = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key.startsWith('on')) item.addEventListener(key.slice(2), value);
    else if (key === 'class') item.className = value;
    else if (key === 'value') item.value = value;
    else if (value === true) item.setAttribute(key, '');
    else if (value !== false && value !== null && value !== undefined) item.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false)
      item.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return item;
}

export function badge(state) {
  return node('span', { class: `badge ${state}` }, stateLabel(state));
}
export function tag(label) {
  return node('span', { class: 'badge' }, label);
}

let busy = false;
/**
 * While an operation runs, controls stay in place and keep focus: buttons are marked
 * aria-disabled and ignore clicks, other controls are disabled unless they hold focus.
 */
export function setBusy(value) {
  busy = value;
  for (const control of document.querySelectorAll('[data-lock]')) lock(control);
}
function lock(control) {
  const off = control.dataset.off === 'true';
  if (control.tagName === 'BUTTON') {
    control.disabled = off;
    if (busy && !off) control.setAttribute('aria-disabled', 'true');
    else control.removeAttribute('aria-disabled');
  } else control.disabled = off || (busy && control !== document.activeElement);
}
/** Marks a control as one that waits while an operation runs. `off` disables it regardless. */
export function lockable(control, off = false) {
  control.dataset.lock = '';
  control.dataset.off = String(!!off);
  lock(control);
  return control;
}
export const isBusy = () => busy;

/** Every button has the same weight unless `primary` is asked for; none is a default action. */
export function button(label, action, { primary = false, disabled = false, id, describedBy } = {}) {
  return lockable(
    node(
      'button',
      {
        type: 'button',
        id,
        class: `button${primary ? ' primary' : ''}`,
        'aria-describedby': describedBy,
        onclick: event => {
          if (busy) event.preventDefault();
          else action(event);
        },
      },
      label,
    ),
    disabled,
  );
}

/** A message on the page. Outcomes are spoken through the persistent live regions, not by role. */
export function notice(message, tone = '', id) {
  return node('div', { class: `notice ${tone}`, id, tabindex: id ? '-1' : null }, message);
}
export function field(label, value, { wide = false, hint } = {}) {
  return node(
    'div',
    { class: wide ? 'wide' : '' },
    node('dt', {}, label),
    node('dd', {}, value, hint && node('span', { class: 'hint' }, hint)),
  );
}
export function formField(label, id, input, hint) {
  return node(
    'div',
    { class: 'field-control' },
    node('label', { for: id }, label),
    input,
    hint && node('p', { class: 'hint', id: `${id}-hint` }, hint),
  );
}
export function empty(title, message, action) {
  return node('div', { class: 'empty' }, node('h2', {}, title), node('p', {}, message), action);
}

/**
 * Replaces one region of the page. Focus stays on the control with the same id when the region
 * held it, a text field keeps its caret, and scrollable lists keep their position.
 */
export function mount(region, ...content) {
  if (!region) return;
  const active = region.contains(document.activeElement) ? document.activeElement : null;
  const focusId = active?.id,
    caret = active && typeof active.selectionStart === 'number' ? [active.selectionStart, active.selectionEnd] : null;
  const scroll = new Map();
  for (const item of region.querySelectorAll('[data-keep-scroll]')) scroll.set(item.id, item.scrollTop);
  region.replaceChildren(...content.flat(Infinity).filter(item => item instanceof Node));
  for (const [id, top] of scroll) {
    const item = id && document.getElementById(id);
    if (item) item.scrollTop = top;
  }
  if (!focusId) return;
  const target = document.getElementById(focusId);
  if (!target || target.disabled) return;
  target.focus({ preventScroll: true });
  if (caret)
    try {
      target.setSelectionRange(caret[0], caret[1]);
    } catch {
      /* Not a text control any more. */
    }
}

/** Moves focus to a heading or notice so it is never left on the document body. */
export function focusOn(...ids) {
  for (const id of ids) {
    const target = id && document.getElementById(id);
    if (target && !target.disabled) {
      target.focus();
      return true;
    }
  }
  return false;
}

const polite = () => document.getElementById('announcement');
const assertive = () => document.getElementById('alert');
/** Speaks an outcome through the persistent live region; `urgent` uses the alert region. */
export function announce(message, urgent = false) {
  const region = urgent ? assertive() : polite();
  if (!region) return;
  // Clearing first makes a repeated message audible again.
  region.textContent = '';
  if (message) queueMicrotask(() => (region.textContent = message));
}
export function clearAnnouncements() {
  for (const region of [polite(), assertive()]) if (region) region.textContent = '';
}

export async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
