import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Compose Tailwind classes safely: `clsx` resolves conditional inputs and
 * `tailwind-merge` collapses conflicts (e.g. `px-4` later replacing `px-2`).
 *
 * Aceternity UI, MagicUI, and shadcn/ui-style primitives all expect a `cn`
 * helper at `@/lib/utils`; this is the single source of truth so the copied
 * source files in `apps/web/src/components/{aceternity,magicui}/` can import
 * it without each shipping its own merge implementation.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Format a timestamp consistently in Indian Standard Time (IST). */
export function formatDateTimeIST(
  value: string | number | Date,
  options: Intl.DateTimeFormatOptions = {},
): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";

  const componentKeys: (keyof Intl.DateTimeFormatOptions)[] = [
    "weekday", "era", "year", "month", "day", "dayPeriod",
    "hour", "minute", "second", "fractionalSecondDigits", "timeZoneName",
  ];
  const hasComponentOptions = componentKeys.some((key) => key in options);

  return new Intl.DateTimeFormat("en-IN", {
    ...(hasComponentOptions ? {} : { dateStyle: "medium", timeStyle: "short" }),
    ...options,
    timeZone: "Asia/Kolkata",
  }).format(date);
}

/** Format a time-only value consistently in Indian Standard Time (IST). */
export function formatTimeIST(value: string | number | Date): string {
  return formatDateTimeIST(value, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}
