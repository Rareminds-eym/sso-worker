/**
 * Mock for cloudflare:workers module in vitest tests.
 * Provides minimal WorkerEntrypoint stub for test compatibility.
 */

export class WorkerEntrypoint<Env = unknown> {
  readonly ctx: ExecutionContext = {} as ExecutionContext;
  readonly env: Env = {} as Env;

  constructor(ctx: ExecutionContext, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(_request: Request): Promise<Response> {
    return new Response('Not implemented', { status: 501 });
  }
}

export class DurableObject<Env = unknown> {
  readonly ctx: DurableObjectState;
  readonly env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
