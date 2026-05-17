export const metricOrder = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

export const metricLabels: Record<string, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  AT: 'Attack Requirements',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  VC: 'Vulnerable Confidentiality',
  VI: 'Vulnerable Integrity',
  VA: 'Vulnerable Availability',
  SC: 'Subsequent Confidentiality',
  SI: 'Subsequent Integrity',
  SA: 'Subsequent Availability',
};

export const metricOptions: Record<string, Array<{ value: string; label: string }>> = {
  AV: [
    { value: 'N', label: 'Network' },
    { value: 'A', label: 'Adjacent' },
    { value: 'L', label: 'Local' },
    { value: 'P', label: 'Physical' },
  ],
  AC: [
    { value: 'L', label: 'Low' },
    { value: 'H', label: 'High' },
  ],
  AT: [
    { value: 'N', label: 'None' },
    { value: 'P', label: 'Present' },
  ],
  PR: [
    { value: 'N', label: 'None' },
    { value: 'L', label: 'Low' },
    { value: 'H', label: 'High' },
  ],
  UI: [
    { value: 'N', label: 'None' },
    { value: 'P', label: 'Passive' },
    { value: 'A', label: 'Active' },
  ],
  VC: impactOptions(),
  VI: impactOptions(),
  VA: impactOptions(),
  SC: impactOptions(),
  SI: impactOptions(),
  SA: impactOptions(),
};

export function defaultMetrics(): Record<string, string> {
  return { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'N', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' };
}

export function vectorFromMetrics(metrics: Record<string, string>): string {
  return `CVSS:4.0/${metricOrder.map((key) => `${key}:${metrics[key] || 'N'}`).join('/')}`;
}

export function metricsFromVector(vector: string): Record<string, string> {
  const metrics = defaultMetrics();
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key in metrics && value) metrics[key] = value;
  }
  return metrics;
}

function impactOptions() {
  return [
    { value: 'H', label: 'High' },
    { value: 'L', label: 'Low' },
    { value: 'N', label: 'None' },
  ];
}
