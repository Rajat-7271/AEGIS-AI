import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { renderCopilotRichText } from './CopilotView';

describe('Copilot response rendering', () => {
  it('renders headings and separate paragraphs', () => {
    const { container } = render(<>{renderCopilotRichText('# Overview\n\nFirst paragraph.\n\nSecond paragraph.')}</>);
    expect(container.querySelector('h1,h2,h3,h4,h5,h6')?.textContent).toBe('Overview');
    expect(container.querySelectorAll('p')).toHaveLength(2);
  });

  it('renders lists and inline formatting', () => {
    const { container } = render(<>{renderCopilotRichText('- **Review** the evidence\n- Check `event_id`')}</>);
    expect(container.querySelectorAll('li')).toHaveLength(2);
    expect(container.querySelector('strong')?.textContent).toBe('Review');
    expect(container.querySelector('code')?.textContent).toBe('event_id');
  });

  it('preserves fenced commands and Windows paths as text', () => {
    const source = '```powershell\nGet-Item C:\\Windows\\System32\n```';
    const { container } = render(<>{renderCopilotRichText(source)}</>);
    expect(container.querySelector('pre code')?.textContent).toContain('Get-Item C:\\Windows\\System32');
  });

  it('renders escaped headings without interpreting HTML', () => {
    const { container } = render(<>{renderCopilotRichText('\\## Overview\n\n<script>alert(1)</script>')}</>);
    expect(container.querySelector('h1,h2,h3,h4,h5,h6')?.textContent).toBe('Overview');
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain('<script>alert(1)</script>');
  });
});
