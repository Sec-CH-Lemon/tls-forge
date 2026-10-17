// What the package's types promise and what they refuse: checked by
// `npm run check`, and never run. Each @ts-expect-error is a call the
// declarations must reject, and tsc fails if one of them is accepted.
import Default, {
  BinaryNotFound,
  Client,
  MAX_REQUEST_BYTES,
  RequestFailed,
  SessionReset,
  TLSForgeError,
  Timeout,
  TransportError,
  Unsupported,
  resolveBinary,
  type BrowserContext,
  type ClientOptions,
  type Hello,
  type Request,
  type RequestOptions,
  type Response,
} from 'tls-forge';

export async function contract(): Promise<void> {
  const options: ClientOptions = {
    profile: 'chrome',
    proxy: 'http://user:pass@proxy.example:8080',
    timeout: 30_000,
    binary: resolveBinary(),
    insecure: false,
    cookieFile: 'cookies.json',
    cookieSet: 'eu',
    onStderr: (line: string) => console.debug(line),
  };
  const client: Client = new Default(options);
  const context: BrowserContext = {
    kind: 'fetch',
    initiator: 'https://shop.example/item/7',
    referrerPolicy: 'no-referrer',
    mode: 'cors',
    credentials: 'include',
  };
  const asked: RequestOptions = {
    headers: { accept: 'application/json' },
    order: ['accept'],
    cookies: ['a=1'],
    browserContext: context,
  };
  const request: Request = { url: 'https://api.shop.example/cart', method: 'POST', body: new Uint8Array([1]), ...asked };
  const responses: Response[] = await Promise.all([
    client.get('https://example.com/', asked),
    client.post('https://example.com/', Buffer.from('x')),
    client.request(request),
  ]);
  const page = responses[0]!;
  const bytes: Buffer = page.content;
  const cookies: string[] | undefined = page.headers['set-cookie'];
  const hello: Hello = await client.hello();
  const speaks: number = hello.protocol;
  const limit: number = MAX_REQUEST_BYTES;
  client.close();

  try {
    await client.get('https://example.com/');
  } catch (err) {
    if (err instanceof SessionReset) {
      const transport: TransportError = err;
      void transport;
    }
    for (const kind of [BinaryNotFound, RequestFailed, Timeout, Unsupported, TransportError, SessionReset]) {
      const base: TLSForgeError = new kind('what happened', { cause: err });
      void base;
    }
  }

  // @ts-expect-error: a timeout is a number of milliseconds
  void new Client({ timeout: '30s' });
  // @ts-expect-error: an option the client does not have
  void new Client({ retries: 3 });
  // @ts-expect-error: a kind Chrome does not send
  void client.request({ url: 'https://a.example/', browserContext: { kind: 'websocket' } });
  // @ts-expect-error: a request needs a url
  void client.request({ method: 'GET' });
  // @ts-expect-error: a body is text or bytes
  void client.post('https://a.example/', 7);
  // @ts-expect-error: a response has no id
  void page.id;
  // @ts-expect-error: a header's values are a list
  const single: string = page.headers['content-type'];
  void [bytes, cookies, speaks, limit, single];
}
