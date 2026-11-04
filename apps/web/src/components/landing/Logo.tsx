import clsx from 'clsx';
import { AegisMark } from '../layout/AegisLogo';

interface LogoProps {
  size?: number;
  withWordmark?: boolean;
  className?: string;
}

/**
 * Vector logo of AEGIS AI with shield and upward-facing A motif.
 */
export function Logo({ size = 36, withWordmark = false, className }: LogoProps) {
  return (
    <span className={clsx('inline-flex items-center gap-3', className)}>
      <AegisMark size={size} />
      {withWordmark && (
        <span className="flex items-baseline gap-1.5 leading-none">
          <span className="font-velvet-display text-xl font-bold tracking-tight text-white">
            AEGIS
          </span>
          <span className="text-xl font-bold tracking-tight text-brand-400">
            AI
          </span>
        </span>
      )}
    </span>
  );
}
