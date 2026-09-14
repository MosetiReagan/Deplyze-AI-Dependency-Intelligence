/**
 * Minimal ANSI colour helper.
 *
 * Deliberately dependency-free and standards-aware: honours `NO_COLOR`,
 * `FORCE_COLOR` and `TERM=dumb`, and never writes escape sequences when the
 * output is not a TTY.
 */
export interface Palette {
  enabled: boolean;
  bold(value: string): string;
  dim(value: string): string;
  red(value: string): string;
  green(value: string): string;
  yellow(value: string): string;
  blue(value: string): string;
  magenta(value: string): string;
  cyan(value: string): string;
  gray(value: string): string;
  underline(value: string): string;
}

export type ColorMode = 'auto' | 'always' | 'never';

function wrap(open: string, close: string, enabled: boolean) {
  return (value: string): string => (enabled ? `\u001b[${open}m${value}\u001b[${close}m` : value);
}

export function createPalette(mode: ColorMode = 'auto', isTTY = process.stdout.isTTY === true): Palette {
  let enabled: boolean;
  if (mode === 'always') enabled = true;
  else if (mode === 'never') enabled = false;
  else {
    enabled =
      isTTY && !('NO_COLOR' in process.env) && process.env.TERM !== 'dumb' && !process.env.CI_NO_COLOR;
  }
  return {
    enabled,
    bold: wrap('1', '22', enabled),
    dim: wrap('2', '22', enabled),
    red: wrap('31', '39', enabled),
    green: wrap('32', '39', enabled),
    yellow: wrap('33', '39', enabled),
    blue: wrap('34', '39', enabled),
    magenta: wrap('35', '39', enabled),
    cyan: wrap('36', '39', enabled),
    gray: wrap('90', '39', enabled),
    underline: wrap('4', '24', enabled),
  };
}

export function severityColor(palette: Palette, severity: string): (value: string) => string {
  switch (severity) {
    case 'critical':
      return (value) => palette.bold(palette.red(value));
    case 'high':
      return (value) => palette.red(value);
    case 'medium':
      return (value) => palette.yellow(value);
    case 'low':
      return (value) => palette.cyan(value);
    default:
      return (value) => palette.gray(value);
  }
}

export function scoreColor(palette: Palette, score: number): (value: string) => string {
  if (score >= 90) return (value) => palette.green(value);
  if (score >= 75) return (value) => palette.cyan(value);
  if (score >= 55) return (value) => palette.yellow(value);
  return (value) => palette.red(value);
}
