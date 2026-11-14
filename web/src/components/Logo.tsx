export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <rect width="32" height="32" rx="8" fill="#1d1d1f" />
      <path d="M16 7l7 3v5c0 4.5-3 8.2-7 9.5-4-1.3-7-5-7-9.5v-5z" fill="#fff" />
    </svg>
  );
}
