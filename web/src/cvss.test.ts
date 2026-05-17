import { describe, expect, it } from 'vitest';
import { defaultMetrics, metricsFromVector, vectorFromMetrics } from './cvss';

describe('CVSS helpers', () => {
  it('builds a CVSS v4 vector from selected metrics', () => {
    const metrics = { ...defaultMetrics(), AV: 'N', AC: 'L', VC: 'H' };
    expect(vectorFromMetrics(metrics)).toContain('CVSS:4.0/AV:N/AC:L');
    expect(vectorFromMetrics(metrics)).toContain('/VC:H/');
  });

  it('imports selected metrics from a pasted vector', () => {
    const metrics = metricsFromVector('CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N');
    expect(metrics.AV).toBe('A');
    expect(metrics.AC).toBe('H');
    expect(metrics.SI).toBe('L');
  });
});
