import { startStdioServer } from '@deplyze/mcp';
import { createContext, type GlobalFlags } from '../context.js';

/**
 * Start the MCP server on stdio.
 *
 * Nothing may be written to stdout except JSON-RPC, so all logging goes to
 * stderr and the process must not print a banner.
 */
export async function mcpCommand(flags: GlobalFlags): Promise<number> {
  const context = await createContext({ ...flags, quiet: true });
  await startStdioServer({ logger: context.logger });
  return 0;
}
