import { useRef, useState } from 'react';
import { defaultSource } from '../inventory-model.mjs';

/**
 * Which source a view works on. Until the reader picks one it is the first source the service
 * lists, also when the list arrives after the view opened. A choice the reader made, "no source"
 * included, is never replaced.
 */
export function useSourceChoice(sources) {
  const [chosen, setChosen] = useState(null);
  const initial = useRef('');
  initial.current = defaultSource(initial.current, sources);
  return [chosen ?? initial.current, setChosen];
}
