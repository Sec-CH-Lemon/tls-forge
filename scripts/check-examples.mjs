import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const scratch = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-examples-'));
const executable = process.platform === 'win32' ? '.exe' : '';
const daemon = path.join(scratch, `fake-daemon${executable}`);
const python = process.env.PYTHON
  ?? (process.platform === 'win32' ? 'python' : 'python3');
const venv = path.join(scratch, 'venv');
const venvPython = process.platform === 'win32'
  ? path.join(venv, 'Scripts', 'python.exe')
  : path.join(venv, 'bin', 'python');

try {
  await run('go', ['build', '-o', daemon, './testdata/fake-daemon'], { cwd: root });
  await run(npmCommand(), ['ci', '--omit=optional'], {
    cwd: path.join(root, 'example', 'node'),
    shell: process.platform === 'win32',
  });
  await run(python, ['-m', 'venv', venv], { cwd: root });
  await run(venvPython, ['-m', 'pip', 'install', '-r', 'requirements.txt'], {
    cwd: path.join(root, 'example', 'python'),
  });

  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"example":"go"}\n');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('example server has no TCP port');
    const output = await run('go', ['run', '.', `http://127.0.0.1:${address.port}/`], {
      cwd: path.join(root, 'example', 'go'),
    });
    expectSuccess('Go', output);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  const env = { ...process.env, TLSFORGE_BIN: daemon };
  const nodeOutput = await run(npmCommand(), ['start', '--', 'https://ok/'], {
    cwd: path.join(root, 'example', 'node'),
    env,
    shell: process.platform === 'win32',
  });
  expectSuccess('Node.js', nodeOutput);

  const pythonOutput = await run(venvPython, ['main.py', 'https://ok/'], {
    cwd: path.join(root, 'example', 'python'),
    env,
  });
  expectSuccess('Python', pythonOutput);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

function npmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function expectSuccess(language, output) {
  if (!output.includes('status: 200') || !output.includes('url:')) {
    throw new Error(`${language} example did not print a successful response`);
  }
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      process.stderr.write(chunk);
    });
    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${command} ${args.join(' ')} exited ${code}\n${stderr}`));
    });
  });
}
