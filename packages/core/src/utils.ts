export const unique = <T>(values: Array<T | null | undefined | false>): T[] =>
  [...new Set(values.filter((value): value is T => Boolean(value)))];
