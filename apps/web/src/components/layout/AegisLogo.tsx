import React from 'react';
import clsx from 'clsx';

interface AegisLogoProps {
  size?: number;
  withWordmark?: boolean;
  className?: string;
  wordmarkClassName?: string;
}

/**
 * AegisMark — High-precision vector insignia for AEGIS AI.
 * Features a protective shield contour with a distinctive upward-facing "A" motif.
 */
export function AegisMark({ size = 32, className }: { size?: number; className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={clsx('shrink-0', className)}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="aegisShieldGrad" x1="32" y1="4" x2="32" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#60A5FA" />
          <stop offset="50%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#1D4ED8" />
        </linearGradient>
        <linearGradient id="aegisShieldInner" x1="32" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#1E3A8A" stopOpacity="0.04" />
        </linearGradient>
        <linearGradient id="aegisGlyphGrad" x1="32" y1="14" x2="32" y2="48" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="100%" stopColor="#E2E8F0" />
        </linearGradient>
        <linearGradient id="aegisCoreGrad" x1="32" y1="20" x2="32" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38BDF8" />
          <stop offset="100%" stopColor="#2563EB" />
        </linearGradient>
      </defs>

      {/* Outer Protective Shield */}
      <path
        d="M32 4 L54 14 V34 C54 47.5 43.5 57 32 60 C20.5 57 10 47.5 10 34 V14 Z"
        fill="url(#aegisShieldInner)"
        stroke="url(#aegisShieldGrad)"
        strokeWidth="2.75"
        strokeLinejoin="round"
      />

      {/* Subtle Inner Guard Line */}
      <path
        d="M32 9 L49 17 V33 C49 43.5 40.5 51.5 32 54.5 C23.5 51.5 15 43.5 15 33 V17 Z"
        stroke="#60A5FA"
        strokeWidth="1"
        strokeOpacity="0.3"
        strokeLinejoin="round"
      />

      {/* Upward-Facing "A" Chevron Silhouette */}
      <path
        d="M21 44 L32 17 L43 44 M25.5 35.5 H38.5"
        stroke="url(#aegisGlyphGrad)"
        strokeWidth="3.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Core Apex Node */}
      <circle cx="32" cy="17" r="2.2" fill="#38BDF8" />

      {/* Inner Upward Focus Accent */}
      <path
        d="M28 35.5 L32 26 L36 35.5"
        stroke="url(#aegisCoreGrad)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * AegisLogo — Combined Mark + Wordmark ("AEGIS" in white, "AI" in blue)
 */
export function AegisLogo({
  size = 32,
  withWordmark = true,
  className,
  wordmarkClassName,
}: AegisLogoProps) {
  return (
    <span className={clsx('inline-flex items-center gap-2.5', className)}>
      <AegisMark size={size} />
      {withWordmark && (
        <span className={clsx('flex items-baseline gap-1.5 font-bold tracking-tight', wordmarkClassName)}>
          <span className="text-white text-base">AEGIS</span>
          <span className="text-brand-400 text-base">AI</span>
        </span>
      )}
    </span>
  );
}

export default AegisLogo;

