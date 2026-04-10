export const unique = <T>(values: Array<T | null | undefined | false>): T[] =>
  [...new Set(values.filter((value): value is T => Boolean(value)))];

export const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> => {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
};

export const headerValue = (
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | null => {
  const value = headers[name];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? null;
};

export const safeResolve = async <T>(operation: () => Promise<T>): Promise<T | null> => {
  try {
    return await operation();
  } catch {
    return null;
  }
};

export const getSiteDomain = (hostname: string): string => {
  const lower = hostname.toLowerCase();
  const parts = lower.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return lower;
  }

  const compoundSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz"]);
  const suffix = parts.slice(-2).join(".");
  if (compoundSuffixes.has(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
};
