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
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

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
    case 'stderr-chunks':
      process.stderr.write('one logical');
      setTimeout(() => {
        process.stderr.write(' line\nsecond line\n');
        reply();
      }, 5);
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
    case 'bad-error':
      reply({ error: {} });
      break;
    case 'bad-status':
      reply({ status: '200' });
      break;
    case 'bad-url':
      reply({ url: 7 });
      break;
    case 'bad-body':
      reply({ body: [] });
      break;
    case 'fixture': {
      // The committed wire format, replayed verbatim except for the id, which
      // the client matches on. See testdata/protocol/README.md.
      const fixture = JSON.parse(
        readFileSync(path.join(here, '..', '..', 'testdata', 'protocol', 'response.json'), 'utf8'),
      );
      process.stdout.write(JSON.stringify({ ...fixture, id: request.id }) + '\n');
      break;
    }
    case 'binary':
      // The bytes a JSON string cannot hold: PNG magic and a stray 0xff.
      reply({
        body: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff]).toString('base64'),
        bodyEncoding: 'base64',
      });
      break;
    case 'echo-body':
      // Hands back what it was sent, so the request direction can be checked.
      reply({ body: request.body ?? '', bodyEncoding: request.bodyEncoding ?? '' });
      break;
    case 'utf8-encoding':
      reply({ body: 'plain text', bodyEncoding: 'utf8' });
      break;
    case 'bad-body-encoding':
      reply({ body: 'x', bodyEncoding: 'rot13' });
      break;
    case 'bad-body-encoding-type':
      reply({ body: 'x', bodyEncoding: 7 });
      break;
    case 'bad-base64':
      reply({ body: '!!not base64!!', bodyEncoding: 'base64' });
      break;
    case 'bad-headers':
      reply({ headers: [] });
      break;
    case 'bad-header-scalar':
      reply({ headers: { broken: 7 } });
      break;
    case 'bad-header-list':
      reply({ headers: { broken: [7] } });
      break;
    case 'bad-cookies':
      reply({ cookies: {} });
      break;
    case 'bad-cookie-item':
      reply({ cookies: [7] });
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
