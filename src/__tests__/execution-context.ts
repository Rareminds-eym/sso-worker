/** Minimal Workers context. Fail explicitly if a test unexpectedly starts tracing. */
export function executionContext(waitUntil: ExecutionContext['waitUntil'] = () => {}): ExecutionContext {
  return {
    waitUntil,
    passThroughOnException() {},
    props: undefined,
    exports: {},
    tracing: new Proxy({} as Tracing, {
      get() { throw new Error('Tracing is not implemented by this test context'); },
    }),
    abort(reason?: unknown) { throw reason ?? new Error('Test execution aborted'); },
  };
}
