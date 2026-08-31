'use strict';
/** Terminal colour helpers, shared by the receiver and the sender. */

const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

const line = (ch = '─') => c('2')(ch.repeat(Math.min(process.stdout.columns || 80, 100)));

module.exports = {
  useColor,
  bold: c('1'),
  dim: c('2'),
  red: c('31'),
  green: c('32'),
  yellow: c('33'),
  blue: c('34'),
  magenta: c('35'),
  cyan: c('36'),
  line,
};
