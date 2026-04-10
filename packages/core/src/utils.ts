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
