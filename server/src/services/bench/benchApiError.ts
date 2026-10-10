/** Every refusal of the bench API: an HTTP status and a sentence that may be
 *  shown at the bench and logged. It never carries a secret's value.
 *  Re-exported by planning.service.ts, where every caller imports it from;
 *  it lives in its own module so the pure helpers can throw it without an
 *  import cycle. */
export class BenchApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string = 'refused',
  ) {
    super(message);
    this.name = 'BenchApiError';
  }
}
