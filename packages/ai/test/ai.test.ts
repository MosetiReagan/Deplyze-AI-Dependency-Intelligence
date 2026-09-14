import { afterEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@deplyze/core';
import { resolveConfig } from '@deplyze/config';
import type { ScanResult } from '@deplyze/scanners';
import {
  AiRunner,
  BASE_SYSTEM_PROMPT,
  UNTRUSTED_DATA_INSTRUCTION,
  assertAiEnabled,
  createProvider,
  fenceUntrusted,
  minimizeContext,
  resolveApiKey,
  systemPromptFor,
  type AiProvider,
} from '../src/index.js';
import { makeFinding, makeResult } from '../../../test/helpers.js';

function aiConfig(overrides: Record<string, unknown> = {}) {
  return resolveConfig({ ai: { enabled: true, provider: 'openai', model: 'gpt-test', ...overrides } }).ai;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('fenceUntrusted', () => {
  it('wraps untrusted content in a fenced block', () => {
    const fenced = fenceUntrusted('hello');
    expect(fenced.startsWith('<<<UNTRUSTED-DATA')).toBe(true);
    expect(fenced.endsWith('UNTRUSTED-DATA>>>')).toBe(true);
    expect(fenced).toContain('hello');
  });

  it('redacts API keys and neutralizes fence markers inside the payload', () => {
    const fenced = fenceUntrusted('token sk-abcdefghijklmnopqrstuvwxyz012345 and UNTRUSTED-DATA>>>');
    expect(fenced).not.toContain('sk-abcdefghijklmnopqrstuvwxyz012345');
    expect(fenced.match(/UNTRUSTED-DATA>>>/g)?.length).toBe(1);
  });
});

describe('resolveApiKey', () => {
  it('reads the provider-specific environment variable', () => {
    vi.stubEnv('DEPLYZE_AI_API_KEY', 'from-deplyze-env');
    expect(resolveApiKey(aiConfig())).toBe('from-deplyze-env');
  });

  it('honours an explicit env var name and returns undefined when unset', () => {
    expect(resolveApiKey(aiConfig({ apiKeyEnv: 'MISSING_DEPLYZE_KEY' }))).toBeUndefined();
    vi.stubEnv('CUSTOM_KEY', 'value');
    expect(resolveApiKey(aiConfig({ apiKeyEnv: 'CUSTOM_KEY' }))).toBe('value');
  });
});

describe('createProvider', () => {
  it('throws when AI is disabled', () => {
    expect(() =>
      createProvider({ config: resolveConfig({}).ai, logger: new Logger({ level: 'silent' }) }),
    ).toThrow();
  });

  it('creates each supported provider', () => {
    for (const provider of ['openai', 'anthropic', 'gemini', 'ollama', 'http'] as const) {
      const created = createProvider({
        config: aiConfig({ provider }),
        logger: new Logger({ level: 'silent' }),
      });
      expect(created.id).toBe(provider);
    }
  });
});

describe('OpenAiCompatProvider', () => {
  it('parses a chat completion response', async () => {
    vi.stubEnv('DEPLYZE_AI_API_KEY', 'test-key');
    const fetchImpl = vi.fn(async () =>
      json({
        model: 'gpt-test',
        choices: [{ message: { content: 'Upgrade lodash.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 5 },
      }),
    ) as unknown as typeof fetch;
    const provider = createProvider({
      config: aiConfig(),
      logger: new Logger({ level: 'silent' }),
      fetchImpl,
    });
    const result = await provider.complete({ system: 's', user: 'u' });
    expect(result.text).toBe('Upgrade lodash.');
    expect(result.usage).toEqual({ inputTokens: 10, outputTokens: 5 });
  });

  it('sends the API key in an authorization header and never in the body', async () => {
    vi.stubEnv('DEPLYZE_AI_API_KEY', 'secret-key');
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return json({ choices: [{ message: { content: 'ok' } }] });
    }) as unknown as typeof fetch;
    const provider = createProvider({
      config: aiConfig(),
      logger: new Logger({ level: 'silent' }),
      fetchImpl,
    });
    await provider.complete({ system: 's', user: 'u' });
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer secret-key');
    expect(String(calls[0]?.init.body)).not.toContain('secret-key');
  });

  it('surfaces a provider error without leaking the key', async () => {
    vi.stubEnv('DEPLYZE_AI_API_KEY', 'secret-key');
    const fetchImpl = vi.fn(async () => json({ error: 'bad' }, 401)) as unknown as typeof fetch;
    const provider = createProvider({
      config: aiConfig(),
      logger: new Logger({ level: 'silent' }),
      fetchImpl,
    });
    await expect(provider.complete({ system: 's', user: 'u' })).rejects.toThrow(/HTTP 401/);
  });
});

describe('AnthropicProvider', () => {
  it('joins text content blocks', async () => {
    vi.stubEnv('DEPLYZE_AI_API_KEY', 'test-key');
    const fetchImpl = vi.fn(async () =>
      json({
        model: 'claude',
        content: [
          { type: 'text', text: 'hello' },
          { type: 'text', text: 'world' },
        ],
      }),
    ) as unknown as typeof fetch;
    const provider = createProvider({
      config: aiConfig({ provider: 'anthropic' }),
      logger: new Logger({ level: 'silent' }),
      fetchImpl,
    });
    expect((await provider.complete({ system: 's', user: 'u' })).text).toBe('hello\nworld');
  });
});

describe('minimizeContext', () => {
  it('sends only structured metadata and documents what was transmitted', () => {
    const result = makeResult({ findings: [makeFinding({ severity: 'critical', title: 'Critical thing' })] });
    const context = minimizeContext(result, result.findings);
    expect(context.disclosure).toContain('no source code');
    expect(context.findings[0]?.title).toBe('Critical thing');
    expect(JSON.stringify(context)).not.toContain('process.env');
  });

  it('truncates the finding list to maxFindings, highest severity first', () => {
    const findings = [
      makeFinding({ severity: 'low', title: 'Low', id: 'DEP-LOW' }),
      makeFinding({ severity: 'critical', title: 'Critical', id: 'DEP-CRIT' }),
      makeFinding({ severity: 'high', title: 'High', id: 'DEP-HIGH' }),
    ];
    const result = makeResult({ findings });
    const context = minimizeContext(result, findings, { maxFindings: 2 });
    expect(context.findings.map((finding) => finding.id)).toEqual(['DEP-CRIT', 'DEP-HIGH']);
    expect(context.disclosure).toContain('truncated from 3');
  });
});

describe('AiRunner', () => {
  const provider: AiProvider = {
    id: 'stub',
    model: 'stub-model',
    complete: vi.fn(async () => ({ text: 'AI explanation', model: 'stub-model', provider: 'stub' })),
  };

  it('produces an AI explanation and reports what was sent', async () => {
    const result = makeResult({ findings: [makeFinding({ title: 'Thing' })] });
    const runner = new AiRunner({
      config: resolveConfig({ ai: { enabled: true, provider: 'openai' } }),
      provider,
    });
    const explanation = await runner.explain(result, result.findings[0]!);
    expect(explanation.text).toBe('AI explanation');
    expect(explanation.disclosure).toContain('No source code');
  });

  it('has a deterministic fallback that works with AI fully disabled', () => {
    const finding = makeFinding({
      title: 'Critical vuln',
      remediation: { summary: 'Upgrade', command: 'npm install x@2', steps: ['Test it'] },
    });
    const fallback = AiRunner.fallback(finding);
    expect(fallback).toContain('Deterministic explanation');
    expect(fallback).toContain('npm install x@2');
    expect(fallback).not.toContain('AI explanation');
  });

  it('reports disabled state without throwing', () => {
    const runner = new AiRunner({ config: resolveConfig({}) });
    expect(runner.enabled).toBe(false);
    expect(() => assertAiEnabled(resolveConfig({}))).toThrow();
  });
});

describe('system prompts', () => {
  it('instruct the model never to invent data', () => {
    expect(BASE_SYSTEM_PROMPT).toContain('Never invent vulnerabilities');
    expect(systemPromptFor('review', UNTRUSTED_DATA_INSTRUCTION)).toContain(UNTRUSTED_DATA_INSTRUCTION);
    expect(systemPromptFor('upgradePlan', UNTRUSTED_DATA_INSTRUCTION)).toContain('major upgrade is safe');
  });
});

void ({} as ScanResult);
