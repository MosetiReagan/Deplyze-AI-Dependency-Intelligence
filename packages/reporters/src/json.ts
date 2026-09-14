import type { Reporter } from './types.js';
import { toJsonResult } from './serialize.js';

export const jsonReporter: Reporter = {
  id: 'json',
  contentType: 'application/json',
  extension: 'json',
  render(result, options = {}) {
    const payload = toJsonResult(result);
    return `${JSON.stringify(payload, null, options.pretty === false ? 0 : 2)}\n`;
  },
};
