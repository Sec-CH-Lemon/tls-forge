#!/usr/bin/env node
// A stand-in for the Go transport, so the client's protocol handling can be
// tested without Go and without a network.
//
// Every behaviour the real transport can exhibit — including the ones that only
// happen when something has gone wrong — is reachable by asking for it in the
// URL. That is the point: the interesting code in the client is what it does
// with a late answer, a garbage line or a dead pipe, and none of those are
// reproducible against a healthy server.

import readline from 'node:readline';

const reader = readline.createInterface({ input: process.stdin });

reader.on('line', (line) => {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    process.stdout.write('{"id":0,"error":"bad request"}\n');
    return;
  }

  const behaviour = new URL(request.url).host;
  const reply = (extra) =>
    process.stdout.write(
      JSON.stringify({
        id: request.id,
        status: 200,
        url: request.url,
        body: JSON.stringify({
          argv: process.argv.slice(2),
          headers: request.headers ?? {},
          order: request.order ?? [],
          cookies: request.setCookie ?? [],
        }),
        headers: { 'content-type': ['application/json'], 'set-cookie': ['a=1', 'b=2'] },
        cookies: [],
        ...extra,
      }) + '\n',
    );

  switch (behaviour) {
    case 'ok':
      reply();
      break;
    case 'error':
      process.stdout.write(JSON.stringify({ id: request.id, error: 'upstream refused' }) + '\n');
      break;
    case 'garbage':
      process.stdout.write('not json at all\n');
      break;
    case 'null-line':
      process.stdout.write('null\n');
      break;
    case 'wrong-id':
      process.stdout.write(JSON.stringify({ id: request.id + 1000, status: 200, body: 'stray' }) + '\n');
      // …then the right one, so the request still completes and the test can
      // assert the stray line was ignored rather than merely slow.
      setTimeout(() => reply(), 10);
      break;
    case 'silent':
      // Never answers. The client's deadline is the only thing that ends this.
      break;
    case 'exit':
      process.exit(3);
      break;
    case 'stderr':
      process.stderr.write('a note on stderr\n');
      reply();
      break;
    case 'legacy-headers':
      reply({ headers: { 'content-type': 'application/json' } });
      break;
    case 'null-headers':
      reply({ headers: null });
      break;
    case 'null-fields':
      reply({ status: null, url: null, body: null, headers: null, cookies: null });
      break;
    case 'trailing-lines':
      reply();
      setTimeout(() => {
        process.stdout.write('not json at all\n');
        process.stdout.write(JSON.stringify({ status: 200, body: 'orphan' }) + '\n');
      }, 10);
      break;
    default:
      reply({ status: 404 });
  }
});
