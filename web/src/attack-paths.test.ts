import { describe, expect, it } from 'vitest';
import { buildAttackPathMarkdown } from './App';
import type { AttackPath } from './types';

describe('attack path packets', () => {
  it('renders selected context without credential secrets', () => {
    const path: AttackPath = {
      id: 'asset-1',
      kind: 'asset',
      created_at: '',
      updated_at: '',
      risk_score: 7,
      checks: ['Linked context is ready for an attack path packet.'],
      payload: { name: 'ci.acme.local', type: 'host', value: '10.0.0.10' },
      findings: [
        {
          id: 'finding-1',
          kind: 'finding',
          created_at: '',
          updated_at: '',
          payload: {
            title: 'Jenkins anonymous read',
            severity: 'Medium',
            status: 'confirmed',
            affected_scope: ['ci.acme.local'],
            summary: 'Anonymous users could view jobs.',
            technical_details: '',
            impact: '',
            remediation: '',
            validation: '',
            references: [],
            open_questions: [],
          },
        },
      ],
      evidence: [
        { id: 'evidence-1', kind: 'evidence', created_at: '', updated_at: '', payload: { kind: 'screenshot', caption: 'Dashboard proof' } },
      ],
      notes: [],
      credentials: [
        { id: 'credential-1', kind: 'credential', created_at: '', updated_at: '', payload: { name: 'svc_backup', username: 'svc_backup', scope: 'ci.acme.local', has_secret: true } },
      ],
    };

    const markdown = buildAttackPathMarkdown(path, { 'finding-1': true, 'evidence-1': true, 'credential-1': true });

    expect(markdown).toContain('# Attack Path: ci.acme.local');
    expect(markdown).toContain('Jenkins anonymous read');
    expect(markdown).toContain('Dashboard proof');
    expect(markdown).toContain('svc_backup');
    expect(markdown).not.toContain('secret');
  });
});
