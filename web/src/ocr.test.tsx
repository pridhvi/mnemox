import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { OCRPanel } from './App';
import type { RecordEnvelope } from './types';

describe('OCRPanel', () => {
  it('renders OCR status and extracted text', () => {
    const record: RecordEnvelope = {
      id: 'evidence-1',
      kind: 'evidence',
      created_at: '',
      updated_at: '',
      payload: {
        kind: 'screenshot',
        original_path: 'jenkins.png',
        ocr_status: 'complete',
        ocr_text: 'Jenkins dashboard visible without authentication',
      },
    };

    render(
      <OCRPanel
        record={record}
        status={{ available: true, engine: 'tesseract', version: 'tesseract 5.3.0' }}
        onExtract={vi.fn()}
      />,
    );

    expect(screen.getByText('complete')).toBeTruthy();
    expect(screen.getByDisplayValue('Jenkins dashboard visible without authentication')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Extract OCR' })).toBeTruthy();
  });
});
