import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const generator = fileURLToPath(new URL('./homebrew-formula.mjs', import.meta.url));
const archives = [
  'tls-forge_1.2.3_darwin_arm64.tar.gz',
  'tls-forge_1.2.3_darwin_amd64.tar.gz',
  'tls-forge_1.2.3_linux_arm64.tar.gz',
  'tls-forge_1.2.3_linux_amd64.tar.gz',
];

test('Homebrew infers the version from release URLs', () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-homebrew-'));
  const archiveDirectory = path.join(temporary, 'archives');
  mkdirSync(archiveDirectory);

  try {
    for (const archive of archives) {
      writeFileSync(path.join(archiveDirectory, archive), archive);
    }

    const generated = spawnSync(
      process.execPath,
      [generator, '--version', '1.2.3', '--archives', archiveDirectory],
      { encoding: 'utf8' },
    );
    assert.equal(generated.status, 0, generated.stderr);
    assert.doesNotMatch(generated.stdout, /^\s*version\s+"/m);
    for (const archive of archives) {
      assert.ok(generated.stdout.includes(`/v1.2.3/${archive}`), archive);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
