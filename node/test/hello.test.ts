// What a transport is, asked before a request relies on it: hello, and a
// browser context sent only to a transport that says it applies one.

import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { chmodSync, mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Client,
  SessionReset,
  TLSForgeError,
  Unsupported,
  type BrowserContext,
  type ClientOptions,
  type Hello,
  type NetworkContext,
  type RequestOptions,
} from '../src/index.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const fakeDaemon = path.join(here, 'fake-daemon.js');
// Where the native fake, which stands in on Windows, finds the committed answers.
process.env.TLSFORGE_PROTOCOL_FIXTURES = path.join(here, '..', '..', 'testdata', 'protocol');
const wrapperDir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-hello-'));
const configuredDaemon = process.env.TLSFORGE_TEST_DAEMON;
let wrapper: string;
if (configuredDaemon) {
  wrapper = path.resolve(configuredDaemon);
} else if (process.platform === 'win32') {
  throw new Error('TLSFORGE_TEST_DAEMON must name the native fake daemon on Windows');
} else {
  wrapper = path.join(wrapperDir, 'wrapper.sh');
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${fakeDaemon}" "$@"\n`);
  chmodSync(wrapper, 0o755);
}

// withTransport runs body with a client whose transport is started with env
// set, and closes it, the variables restored, after.
async function withTransport(
  env: Record<string, string>,
  body: (client: Client) => Promise<void>,
  options: ClientOptions = {},
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(env)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  const client = new Client({ binary: wrapper, ...options });
  try {
    await body(client);
  } finally {
    client.close();
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

// seen is what the transport had read by the time it answered a plain request.
async function seen(client: Client) {
  return JSON.parse((await client.get('https://ok/')).body);
}

// COLD_START is a deadline with time in it for a transport to start and
// answer, however slowly this machine starts one: a binary just built has
// taken over half a second to answer on macOS, and a loaded machine is slower.
const COLD_START = 5_000;

// pastDeadline makes ask with setTimeout in the test's hands, and lets every
// deadline it set pass at once. A client has one timeout, for starting a
// transport as for any request: one short enough to wait out would be too
// short for a start the test makes after it, and on the test's clock it can
// be COLD_START and cost nothing. Nothing is in flight when ask is made: the
// test's clearTimeout does not clear a deadline set on the real clock, which
// would pass later. The real clock is back for what follows.
function pastDeadline<T>(t: TestContext, ask: () => T): T {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const asked = ask();
    t.mock.timers.runAll();
    return asked;
  } finally {
    t.mock.timers.reset();
  }
}

test('a transport says the protocol it speaks and what it can do, once', async () => {
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'one,two,catalogue_json_v1,network_hints_estimator_v1' }, async (client) => {
    const first = await client.hello();
    assert.deepEqual(first, { protocol: 3, capabilities: ['one', 'two', 'catalogue_json_v1', 'network_hints_estimator_v1'], engine_major: 1, version: '1.0.1' });
    // A copy each time: what one caller does with it is not the next's.
    first.capabilities.push('three');
    assert.deepEqual(await client.hello(), { protocol: 3, capabilities: ['one', 'two', 'catalogue_json_v1', 'network_hints_estimator_v1'], engine_major: 1, version: '1.0.1' });
    const { controls, requests } = await seen(client);
    assert.equal(controls, 1);
    assert.equal(requests, 1);
  });
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: '' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 3, capabilities: [], engine_major: 1, version: '1.0.1' });
  });
});

test('a transport newer than this package is read for what it says it can do', async () => {
  // A protocol after 2, and a capability no package knows yet, are no reason
  // to refuse what both know.
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'newer' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 7, capabilities: ['browser_context', 'teleport', 'catalogue_json_v1', 'network_hints_estimator_v1', 'network_context_v1'], engine_major: 1, version: '1.0.1' });
    const context: BrowserContext = { kind: 'fetch', initiator: 'https://example.com/' };
    const answer = JSON.parse((await client.get('https://ok/', { browserContext: context })).body);
    assert.deepEqual(answer.browser, context);
  });
});

test('a transport older than the question speaks protocol 1', async () => {
  await withTransport({ TLSFORGE_TEST_PROTOCOL: '1' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 1, capabilities: [] });
  });
});

test('the committed answers to hello read as they say', async () => {
  for (const [mode, want] of [
    ['fixture', { protocol: 3, capabilities: ['browser_context', 'engine_major', 'catalogue_json_v1', 'network_hints_estimator_v1', 'network_context_v1'], engine_major: 1, version: '1.0.1' }],
    ['fixture-old', { protocol: 1, capabilities: [] }],
  ] as [string, Hello][]) {
    await withTransport({ TLSFORGE_TEST_PROTOCOL: mode }, async (client) => {
      assert.deepEqual(await client.hello(), want);
    });
  }
});

test('an answer to hello that says nothing it can is a bad response, asked again', async () => {
  for (const mode of ['bad', 'bad-capabilities', 'no-capabilities', 'low']) {
    await withTransport({ TLSFORGE_TEST_PROTOCOL: mode }, async (client) => {
      await assert.rejects(client.hello(), /^TransportError: tlsforge: bad response: hello must give a protocol from 2/);
      await assert.rejects(client.hello(), /bad response/);
      await assert.rejects(client.get('https://ok/'), /bad response/);
    });
  }
});

test('a transport that does not answer hello has said nothing, and is asked again', async (t) => {
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'silent' }, async (client) => {
    await assert.rejects(pastDeadline(t, () => client.hello()), /request timed out/);
    // A question was made in no session: it is asked of the next transport,
    // and the next request is the one told its session has gone.
    await assert.rejects(pastDeadline(t, () => client.hello()), /request timed out/);
    await assert.rejects(pastDeadline(t, () => client.get('https://ok/')), /request timed out/);
  }, { timeout: COLD_START });
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'exit' }, async (client) => {
    await assert.rejects(client.hello(), /transport exited \(code 3\)/);
  });
});

test('a question asked after a session went leaves the next request to be told', async (t) => {
  await withTransport({}, async (client) => {
    await assert.rejects(pastDeadline(t, () => client.get('https://silent/')), /request timed out/);
    assert.deepEqual(await client.hello(), { protocol: 3, capabilities: ['browser_context', 'engine_major', 'catalogue_json_v1', 'network_hints_estimator_v1', 'network_context_v1'], engine_major: 1, version: '1.0.1' });
    await assert.rejects(client.get('https://ok/'), (err: Error) => err.name === 'SessionReset');
    assert.equal((await seen(client)).requests, 1);
  }, { timeout: COLD_START });
});

test('a closed client asks nothing', async () => {
  const client = new Client({ binary: wrapper });
  client.close();
  await assert.rejects(client.hello(), /closed/);
});

test('a browser context goes to a transport that applies one, and to no other', async () => {
  const context: BrowserContext = { kind: 'fetch', initiator: 'https://example.com/' };
  for (const [env, protocol] of [[{ TLSFORGE_TEST_CAPABILITIES: 'other,catalogue_json_v1,network_hints_estimator_v1' }, 3]] as const) {
    await withTransport(env, async (client) => {
      const refused = await client.get('https://ok/', { browserContext: context }).then(
        () => assert.fail('sent'),
        (err: unknown) => err,
      );
      assert.ok(refused instanceof Unsupported);
      assert.equal(refused.name, 'Unsupported');
      assert.equal(
        refused.message,
        `tlsforge: the tls-forge at ${wrapper} speaks protocol ${protocol} and does not apply browser ` +
          'contexts; the request was not sent',
      );
      // Asked, and nothing sent: the plain request after it is the first.
      assert.equal((await seen(client)).requests, 1);
    });
  }
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'browser_context,catalogue_json_v1,network_hints_estimator_v1' }, async (client) => {
    const answer = JSON.parse((await client.post('https://ok/', 'x', { browserContext: context })).body);
    // Sent as the protocol names it, and under no other name.
    assert.deepEqual(answer.browser, context);
    assert.ok(answer.sent.includes('browser'));
    assert.ok(!answer.sent.includes('browserContext'));
    assert.equal(answer.bodyLength, 1);
  });
  // Without one, nothing is asked.
  await withTransport({}, async (client) => {
    const answer = await seen(client);
    assert.equal(answer.controls, 1);
    assert.equal(answer.browser, null);
    assert.ok(!answer.sent.includes('browser'));
  });
});

test('a browser context goes with every key as the protocol names it', async () => {
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'browser_context,catalogue_json_v1,network_hints_estimator_v1' }, async (client) => {
    const context: BrowserContext = {
      kind: 'fetch',
      initiator: 'https://shop.example/item/7',
      referrerPolicy: 'origin',
      mode: 'cors',
      credentials: 'include',
    };
    const answer = JSON.parse((await client.get('https://ok/', { browserContext: context })).body);
    assert.deepEqual(answer.browser, context);
  });
});

test('a browser context that is no object, or has a key the protocol does not, is a mistake in the call', async () => {
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'browser_context,catalogue_json_v1,network_hints_estimator_v1' }, async (client) => {
    for (const [context, says] of [
      ['fetch', /^tlsforge: browserContext must be an object$/],
      [['kind', 'fetch'], /^tlsforge: browserContext must be an object$/],
      // The Python package's spelling of a key is not the protocol's.
      [{ kind: 'fetch', referrer_policy: 'origin' },
        /^tlsforge: browserContext has no key "referrer_policy"; it takes kind, initiator, referrerPolicy, mode, credentials$/],
      [{ kind: 'fetch', teleport: true }, /^tlsforge: browserContext has no key "teleport"/],
    ] as [unknown, RegExp][]) {
      await assert.rejects(client.get('https://ok/', { browserContext: context as never }), (err: Error) => {
        assert.ok(err instanceof TypeError && !(err instanceof TLSForgeError), err.name);
        assert.match(err.message, says);
        return true;
      });
    }
    // Said before anything was asked; and null is none, as it is to the daemon.
    // @ts-expect-error -- null, which the types do not offer
    const answer = JSON.parse((await client.get('https://ok/', { browserContext: null })).body);
    assert.equal(answer.controls, 1);
    assert.equal(answer.requests, 1);
    assert.ok(!answer.sent.includes('browser'));
  });
});

test('every request requires the exact SDK engine major before URL or cookie transmission', async () => {
  for (const major of ['missing', 'null', '0', '7', '2', '3', '4', '5', '6', '8', '-1', '1.5', '"1"', 'true']) {
    const log = path.join(wrapperDir, `engine-${encodeURIComponent(major)}.jsonl`);
    await withTransport({ TLSFORGE_TEST_ENGINE_MAJOR: major, TLSFORGE_TEST_WIRE_LOG: log }, async (client) => {
      for (const options of [{}, { browserContext: { kind: 'navigation' } }] as RequestOptions[]) {
        await assert.rejects(client.get('https://must-not-resolve.invalid/', { cookies: ['secret=never-sent'], ...options }), (err: Error) => {
          assert.ok(err instanceof Unsupported);
          assert.match(err.message, /engine_major .*SDK engine major 1; request was not sent/);
          return true;
        });
      }
      const lines = JSON.parse('[' + readFileSync(log, 'utf8').trim().split('\n').join(',') + ']');
      assert.equal(lines.length, 1);
      assert.equal(lines[0].control, 'hello');
      assert.equal(lines[0].url, undefined);
      assert.equal(lines[0].setCookie, undefined);
    });
  }
  for (const mode of ['1', 'fixture-old']) {
    await withTransport({ TLSFORGE_TEST_PROTOCOL: mode }, async (client) => {
      await assert.rejects(client.get('https://must-not-resolve.invalid/'), Unsupported);
    });
  }
  for (const version of ['0.1.0', '7.0.0', 'bad']) {
    await withTransport({ TLSFORGE_TEST_ENGINE_VERSION: version }, async (client) => {
      await assert.rejects(client.get('https://must-not-resolve.invalid/'), Unsupported);
    });
  }
  await withTransport({}, async (client) => {
    const answer = await seen(client);
    assert.ok(answer.sent.includes('engine_major'));
    assert.equal(answer.controls, 1);
  });
});

test('a replacement process must pass its own engine handshake', async () => {
  const log = path.join(wrapperDir, 'replacement-engine.jsonl');
  await withTransport({ TLSFORGE_TEST_WIRE_LOG: log, TLSFORGE_TEST_ENGINE_MAJOR: '1' }, async (client) => {
    await client.get('https://ok/first');
    process.env.TLSFORGE_TEST_ENGINE_MAJOR = '0';
    await assert.rejects(client.get('https://silent/'), /timed out/);
    await assert.rejects(client.get('https://must-not-resolve.invalid/'), Unsupported);
    const lines = readFileSync(log, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(lines.filter((line) => line.control === 'hello').length, 2);
    assert.equal(lines.filter((line) => line.url?.includes('must-not-resolve')).length, 0);
  }, { timeout: 1000 });
});


test('only ambient TLS key logging is removed on every daemon start', async () => {
 const kept = {
  QUIC_GO_DISABLE_ECN:'1', QUIC_GO_DISABLE_GSO:'1',
  QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING:'1', QUIC_GO_LOG_LEVEL:'ERROR',
  QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING:'true', GODEBUG:'http2client=0',
 };
 await withTransport({...kept, SSLKEYLOGFILE:'never-export', sslkeylogfile:'never-export'},async (client) => {
  for (let i=0;i<2;i++) {
   const answer=await seen(client);
   assert.equal(answer.env.SSLKEYLOGFILE,null);
   assert.equal(answer.env.sslkeylogfile,null);
   for(const [key,value] of Object.entries(kept)) assert.equal(answer.env[key],value);
   assert.equal(process.env.SSLKEYLOGFILE,'never-export');
   if(i===0) {
    await assert.rejects(client.get('https://silent/'), /timed out/);
    await assert.rejects(client.get('https://ok/'), SessionReset);
   }
  }
 },{timeout:1000});
});

test('network metadata is snapshotted, typed and sent by its protocol name', async () => {
 await withTransport({}, async (client) => {
  const input: NetworkContext={type:'wifi',id:'network-😀',generation:7,signal:0};
  const answer=client.get('https://ok/',{networkContext:input});
  input.id='owner-later-edit';input.signal=4;
  const received=JSON.parse((await answer).body);
  assert.deepEqual(received.network,{type:'wifi',id:'network-😀',generation:7,signal:0});
  assert.ok(received.sent.includes('network'));
  assert.ok(!received.sent.includes('networkContext'));
  assert.equal(JSON.parse((await client.get('https://ok/',{networkContext:{type:'none',id:'',generation:0,signal:null}})).body).network.signal,null);
 });
});

test('malformed network metadata is rejected before discovery or a request', async () => {
 const good: NetworkContext={type:'wifi',id:'network-a',generation:0,signal:null};
 const invalid: unknown[]=[[],false,'wifi',{}, {type:"wifi",id:"a",generation:0,rtt:1}, {...good,rtt:100}, {...good,signal:undefined}, {...good,type:'made-up'}, {...good,id:17}, {...good,id:'\ud800'}, {...good,id:'x'.repeat(4097)}, {...good,generation:-1}, {...good,generation:2**53}, {...good,generation:1.5}, {...good,signal:false}, {...good,signal:-1}, {...good,signal:5}];
 await withTransport({},async(client)=>{
  for(const value of invalid) await assert.rejects(client.get('https://ok/',{networkContext:value as never}),TypeError);
  const answer=await seen(client);assert.equal(answer.controls,1);assert.equal(answer.requests,1);
 });
});

test('same-major legacy daemons cannot silently ignore catalogue or estimator policy', async () => {
 for(const caps of ['browser_context,engine_major','browser_context,engine_major,catalogue_json_v1']){
  const log=path.join(wrapperDir,`legacy-${caps.length}.jsonl`);
  await withTransport({TLSFORGE_TEST_CAPABILITIES:caps,TLSFORGE_TEST_WIRE_LOG:log},async(client)=>{
   assert.equal((await client.hello()).engine_major,1);
   await assert.rejects(client.get('https://must-not-send/'),/lacks required capabilities.*request was not sent/);
   const lines=readFileSync(log,'utf8').trim().split('\n').map((line) => JSON.parse(line));
   assert.equal(lines.length,1);assert.equal(lines[0].control,'hello');
  });
 }
 await withTransport({TLSFORGE_TEST_CAPABILITIES:'catalogue_json_v1,network_hints_estimator_v1'},async(client)=>{
  await assert.rejects(client.get('https://must-not-send/',{networkContext:{type:'wifi',id:'a',generation:0,signal:null}}),/does not apply network contexts/);
  assert.equal((await seen(client)).requests,1);
 });
});
