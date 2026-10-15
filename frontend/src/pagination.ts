export const PAGE_SIZES = [10, 25, 50, 100];
export const EMBEDDED_PAGE_SIZES = [10, 25, 50];

export function pageSize(value: string | null, options = PAGE_SIZES, fallback = 25): number {
  const size = Number(value);
  return options.includes(size) ? size : fallback;
}
