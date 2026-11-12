import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import crypto, { createHash, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardError } from '@shieldaai/agent-guard';
import { DurableExecutor, ExecutorError, createPrivateFileTools } from '../dist/index.js';
import {
  ArtifactBroker,
  createSandboxTool,
  readSandboxArchive,
  runDockerSandbox,
  runGovernedSandbox,
  writeReviewedExports,
} from '../dist/entry-sandbox.js';
import { readWorkspaceInput } from '../dist/workspace-input.js';
import { MAX_PATH_BYTES, MAX_PATH_COUNT, portablePathListProblem, portablePathProblem } from '../dist/path-rules.js';

const fixture = JSON.parse(
  fs.readFileSync(new URL('./fixtures/packed-build-attestation.json', import.meta.url), 'utf8'),
);
const image = `alpine@sha256:${'a'.repeat(64)}`;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const posix = process.platform === 'darwin' || process.platform === 'linux';

function directory(t, prefix = 'agent-guard-release-sandbox-') {
  const dir = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function host(t) {
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
  const broker = new ArtifactBroker({ key: randomBytes(32), keyId: 'release-host' });
  t.after(() => {
    broker.close();
    executor.close();
  });
  executor.createTask({
    id: 'task',
    principalId: 'operator',
    tenantId: 'tenant',
    grants: [],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  return { executor, broker };
}

/** Tar writer for the three ways a guest tar can spell a name: ustar, GNU long name, pax. */
function tar(entries) {
  const blocks = [];
  const header = (name, type, size, gnu) => {
    const block = Buffer.alloc(512);
    Buffer.from(name).copy(block, 0, 0, 100);
    block.write('0000600\0', 100, 8);
    block.write('0001750\0', 108, 8);
    block.write('0001750\0', 116, 8);
    block.write(size.toString(8).padStart(11, '0') + '\0', 124, 12);
    block.write('00000000000\0', 136, 12);
    block.fill(32, 148, 156);
    block.write(type, 156);
    block.write(gnu ? 'ustar  \0' : 'ustar\x0000', 257, 'latin1');
    const checksum = block.reduce((sum, value) => sum + value, 0);
    block.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    return block;
  };
  const body = data => [data, Buffer.alloc((512 - (data.length % 512)) % 512)];
  for (const { path, data = '', type = '0', format = 'ustar', records } of entries) {
    const bytes = Buffer.from(data);
    const name = Buffer.isBuffer(path) ? path : Buffer.from(path);
    if (format === 'gnu') {
      const long = Buffer.concat([name, Buffer.alloc(1)]);
      blocks.push(header('././@LongLink', 'L', long.length, true), ...body(long));
    } else if (format === 'pax') {
      const lines = (records ?? [['path', name.toString()]]).map(([key, value]) => {
        const rest = ` ${key}=${value}\n`;
        let length = Buffer.byteLength(rest) + 1;
        while (Buffer.byteLength(String(length) + rest) !== length) length++;
        return String(length) + rest;
      });
      const extended = Buffer.from(lines.join(''));
      blocks.push(header('PaxHeader/entry', 'x', extended.length, false), ...body(extended));
    }
    if (type !== 'none') blocks.push(header(name, type, bytes.length, format === 'gnu'), ...body(bytes));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}

/** Replaces the Docker CLI. `reply(args)` returns { code, stdout, stderr } for one invocation. */
function fakeDocker(t, reply) {
  const calls = [];
  const original = childProcess.spawn;
  childProcess.spawn = (command, args) => {
    assert.equal(command, 'docker');
    calls.push(args);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.pid = 1;
    child.kill = () => true;
    const answer = reply(args) ?? {};
    setImmediate(() => {
      if (answer.stdout) child.stdout.emit('data', Buffer.from(answer.stdout));
      if (answer.stderr) child.stderr.emit('data', Buffer.from(answer.stderr));
      child.emit('close', answer.code ?? 0);
    });
    return child;
  };
  syncBuiltinESMExports();
  const dockerHost = process.env.DOCKER_HOST;
  delete process.env.DOCKER_HOST;
  t.after(() => {
    childProcess.spawn = original;
    syncBuiltinESMExports();
    if (dockerHost !== undefined) process.env.DOCKER_HOST = dockerHost;
  });
  return calls;
}
/** A healthy local Linux daemon; `overrides(args)` may answer any step differently. */
function healthyDocker(t, overrides = () => undefined) {
  return fakeDocker(t, args => {
    const answer = overrides(args);
    if (answer) return answer;
    if (args[0] === 'context') return { stdout: '"unix:///var/run/docker.sock"\n' };
    if (args[0] === 'version') return { stdout: 'linux\n' };
    if (args[0] === 'info')
      return {
        stdout: JSON.stringify({
          MemoryLimit: true,
          SwapLimit: true,
          PidsLimit: true,
          CpuCfsQuota: true,
          SecurityOptions: ['name=seccomp,profile=builtin', 'name=cgroupns'],
        }),
      };
    if (args[0] === 'image') return { stdout: JSON.stringify({ Os: 'linux', RepoDigests: [image], Config: {} }) };
    return {};
  });
}
const isCommand = args => args[0] === 'exec' && args[1] === '--workdir=/workspace';
const isArchive = args => args[0] === 'exec' && args.includes('/bin/tar');

test('one path rule: the adapter, the sandbox, receipts and build policy accept and reject the same names', t => {
  const { broker } = host(t);
  const tools = createPrivateFileTools({ directory: directory(t), tenantId: 'tenant', resourcePrefix: 'files' });
  const empty = tar([]);
  const validators = {
    adapter: path => tools.read.parse({ path }),
    sandbox: path => {
      try {
        readSandboxArchive(empty, [path], 100);
      } catch (error) {
        // A portable name gets as far as "that file is not in the archive".
        if (error.code !== 'SANDBOX_EXPORT_MISSING') throw error;
      }
    },
    receipt: path => broker.classifyArtifact({ content: Buffer.from('x'), path, tenantId: 'tenant', origin: 'upload' }),
    buildPolicy: path =>
      new ArtifactBroker({
        key: randomBytes(32),
        keyId: 'policy',
        buildPolicy: { artifacts: [{ ...fixture.rule, path }] },
      }).close(),
  };
  const accepted = [
    'a.txt',
    'nested/dir/file.tar.gz',
    `d/${'x'.repeat(MAX_PATH_BYTES - 2)}`,
    `${'é'.repeat(MAX_PATH_BYTES / 2)}`,
    'café/日本語.txt',
  ];
  const rejected = [
    ['x'.repeat(MAX_PATH_BYTES + 1), 'PATH_TOO_LONG'],
    // 121 characters but 242 bytes: the limit is bytes, which is what tar and filesystems carry.
    ['é'.repeat(MAX_PATH_BYTES / 2 + 1), 'PATH_TOO_LONG'],
    ['x'.repeat(1024), 'PATH_TOO_LONG'],
    ['e\u0301.txt', 'PATH_NOT_NFC'],
    ['a*b', 'PATH_CHARACTER'],
    ['a?b', 'PATH_CHARACTER'],
    ['a"b', 'PATH_CHARACTER'],
    ['a<b', 'PATH_CHARACTER'],
    ['a>b', 'PATH_CHARACTER'],
    ['a|b', 'PATH_CHARACTER'],
    ['C:/x', 'PATH_CHARACTER'],
    ['a\\b', 'PATH_CHARACTER'],
    ['a\u0001b', 'PATH_CHARACTER'],
    ['a\ud800b', 'PATH_CHARACTER'],
    ['../escape', 'PATH_SEGMENT'],
    ['/absolute', 'PATH_SEGMENT'],
    ['a//b', 'PATH_SEGMENT'],
    ['a/', 'PATH_SEGMENT'],
    ['a./b', 'PATH_SEGMENT'],
    ['a /b', 'PATH_SEGMENT'],
    ['CON', 'PATH_RESERVED'],
    ['dir/nul.txt', 'PATH_RESERVED'],
    ['.agent-guard-provenance.json', 'PATH_RESERVED'],
    ['.Agent-Guard-Provenance.JSON', 'PATH_RESERVED'],
    ['', 'PATH_EMPTY'],
    [5, 'PATH_NOT_STRING'],
  ];
  const codes = {
    adapter: 'ADAPTER_PATH_INVALID',
    sandbox: 'SANDBOX_PATH_INVALID',
    receipt: 'ARTIFACT_INVALID',
    buildPolicy: 'BUILD_PROVENANCE_INVALID',
  };
  for (const [name, validate] of Object.entries(validators)) {
    for (const path of accepted) {
      assert.equal(portablePathProblem(path), undefined);
      assert.doesNotThrow(() => validate(path), `${name} must accept ${JSON.stringify(path).slice(0, 40)}`);
    }
    for (const [path, problem] of rejected) {
      assert.equal(portablePathProblem(path), problem);
      assert.throws(
        () => validate(path),
        error => {
          assert.equal(error.name, 'ExecutorError', `${name}: ${String(path).slice(0, 40)}`);
          assert.equal(error.code, codes[name]);
          // Build policy answers every rejection the same way; the others name the broken rule.
          assert.equal(error.detail, name === 'buildPolicy' ? undefined : problem);
          return true;
        },
        `${name} must reject ${JSON.stringify(path).slice(0, 40)}`,
      );
    }
  }
});

test('path lists reject case collisions, file-against-directory clashes and more than 256 entries everywhere', t => {
  const { executor, broker } = host(t);
  const workspace = directory(t);
  const colliding = [
    ['x.txt', 'X.TXT'],
    ['dir/a.txt', 'DIR/b.txt'],
    ['a', 'a/b'],
    ['A/b', 'a'],
    ['straße', 'STRASSE'],
  ];
  const tooMany = Array.from({ length: MAX_PATH_COUNT + 1 }, (_, index) => `f${index}`);
  const invalid = detail => error => {
    assert.equal(error.code, 'SANDBOX_PATH_INVALID');
    assert.equal(error.detail, detail);
    return true;
  };
  const tool = files => ({
    name: 'shell',
    executor,
    broker,
    profile: { image },
    workspace,
    tenantId: 'tenant',
    resourceId: 'workspace',
    origin: 'test',
    onResult: () => 'id',
    ...files,
  });
  for (const [files, detail] of [...colliding.map(files => [files, 'PATH_COLLISION']), [tooMany, 'PATH_COUNT']]) {
    assert.equal(portablePathListProblem(files), detail);
    assert.throws(() => readSandboxArchive(tar([]), files, 100), invalid(detail));
    assert.throws(
      () =>
        writeReviewedExports(
          { exports: [] },
          files.map(path => ({ path, sha256: '0'.repeat(64) })),
          'unused',
        ),
      error =>
        files.length > MAX_PATH_COUNT ? error.code === 'SANDBOX_EXPORT_REVIEW_INVALID' : invalid(detail)(error),
    );
    // The tool refuses at creation what the run would refuse later.
    assert.throws(() => createSandboxTool(tool({ inputFiles: files })), invalid(detail));
    assert.throws(() => createSandboxTool(tool({ inputFiles: [], exportFiles: files })), invalid(detail));
  }
  assert.equal(portablePathListProblem(['dir/a.txt', 'dir/b.txt', 'other/a.txt']), undefined);
  // A sparse list has no value to check at the hole.
  assert.equal(portablePathListProblem(Object.assign([], { 1: 'b' })), 'PATH_LIST_INVALID');
  assert.equal(portablePathListProblem('a.txt'), 'PATH_LIST_INVALID');
});

test('the archive reader carries every accepted path: ustar prefix, GNU long names and pax', () => {
  const longest = `out/${'n'.repeat(MAX_PATH_BYTES - 4)}`;
  const unicode = `out/${'日'.repeat(60)}.bin`;
  assert.equal(Buffer.byteLength(longest), MAX_PATH_BYTES);
  for (const format of ['gnu', 'pax']) {
    for (const name of [longest, unicode]) {
      const files = readSandboxArchive(
        tar([
          { path: `./${name}`, data: 'payload', format },
          { path: './short.txt', data: 'short' },
        ]),
        [name, 'short.txt'],
        100,
      );
      assert.deepEqual(
        files.map(file => [file.path, Buffer.from(file.contentBase64, 'base64').toString()]),
        [
          [name, 'payload'],
          ['short.txt', 'short'],
        ],
      );
    }
  }
  // pax bookkeeping keys are ignored; keys that change which bytes belong to the entry are refused.
  const timed = tar([
    {
      path: 'a.txt',
      data: 'a',
      format: 'pax',
      records: [
        ['mtime', '1700000000.5'],
        ['path', 'renamed.txt'],
      ],
    },
  ]);
  assert.equal(readSandboxArchive(timed, ['renamed.txt'], 10)[0].path, 'renamed.txt');
  const refused = [
    [tar([{ path: `./${longest}x`, data: 'x', format: 'gnu' }]), 'PATH_TOO_LONG'],
    [tar([{ path: `./${longest}x`, data: 'x', format: 'pax' }]), 'PATH_TOO_LONG'],
    [tar([{ path: Buffer.from([0x61, 0xff, 0x62]), data: 'x' }]), 'ARCHIVE_NAME'],
    [
      tar([{ path: Buffer.concat([Buffer.from('./'), Buffer.alloc(150, 0xff)]), data: 'x', format: 'gnu' }]),
      'ARCHIVE_NAME',
    ],
    [tar([{ path: 'a', data: 'x', format: 'pax', records: [['size', '9']] }]), 'ARCHIVE_EXTENSION'],
    [tar([{ path: 'a', data: 'x', format: 'pax', records: [['linkpath', '/etc/passwd']] }]), 'ARCHIVE_EXTENSION'],
    [tar([{ path: 'a', data: 'x', format: 'pax', records: [['GNU.sparse.major', '1']] }]), 'ARCHIVE_EXTENSION'],
    [
      tar([
        { path: 'a', format: 'gnu', type: 'none' },
        { path: 'b', data: 'x', format: 'gnu' },
      ]),
      'ARCHIVE_EXTENSION',
    ],
    [tar([{ path: 'a', format: 'gnu', type: 'none' }]), 'ARCHIVE_INCOMPLETE'],
    [tar([{ path: 'a', data: 'x', type: 'g' }]), 'ARCHIVE_ENTRY_TYPE'],
    [tar([{ path: 'a', type: '2' }]), 'ARCHIVE_ENTRY_TYPE'],
    [
      tar([
        { path: 'x', data: '1' },
        { path: 'X', data: '2' },
      ]),
      'ARCHIVE_DUPLICATE',
    ],
  ];
  for (const [archive, detail] of refused)
    assert.throws(
      () => readSandboxArchive(archive, [], 100),
      error => error.code === 'SANDBOX_ARCHIVE_INVALID' && error.detail === detail,
      detail,
    );
  assert.throws(() => readSandboxArchive(tar([{ path: 'a', data: 'four' }]), ['a'], 3), {
    code: 'SANDBOX_EXPORT_LIMIT',
  });
  assert.throws(() => readSandboxArchive(tar([]), ['a'], 3), { code: 'SANDBOX_EXPORT_MISSING' });
});

test('the broker refuses an unusable export path before reading inputs, tainting the task or starting Docker', async t => {
  const { executor, broker } = host(t);
  const workspace = directory(t);
  fs.writeFileSync(join(workspace, 'input.txt'), 'input');
  const calls = healthyDocker(t);
  for (const [exportFiles, detail] of [
    [['report*.txt'], 'PATH_CHARACTER'],
    [['.agent-guard-provenance.json'], 'PATH_RESERVED'],
    [['e\u0301.txt'], 'PATH_NOT_NFC'],
    [['x'.repeat(MAX_PATH_BYTES + 1)], 'PATH_TOO_LONG'],
    [['Out.txt', 'out.txt'], 'PATH_COLLISION'],
  ]) {
    await assert.rejects(
      runGovernedSandbox(executor, 'task', {
        broker,
        origin: 'shell',
        profile: { image },
        workspace,
        inputFiles: ['input.txt'],
        exportFiles,
        command: ['/bin/true'],
      }),
      error => error.code === 'SANDBOX_PATH_INVALID' && error.detail === detail,
      detail,
    );
  }
  assert.equal(calls.length, 0, 'no Docker command may run for a request that cannot complete');
  assert.equal(executor.snapshot('task').sensitive, false, 'a refused request must not taint the task');
});

test('a governed run signs the bytes the command wrote and hashes each artifact once', async t => {
  const { executor, broker } = host(t);
  const workspace = directory(t);
  const input = randomBytes(70_001);
  const exported = randomBytes(50_003);
  const exportName = `out/${'r'.repeat(180)}.bin`;
  // Not valid UTF-8: decoding to text and encoding again yields different bytes.
  const stdout = Buffer.from([0xff, 0xfe, 0x00, 0x41, 0xc3]);
  const stderr = Buffer.from('warning\n');
  fs.writeFileSync(join(workspace, 'input.bin'), input);
  const calls = healthyDocker(t, args => {
    if (isCommand(args)) return { stdout, stderr };
    if (isArchive(args))
      return {
        stdout: tar([
          { path: './input.bin', data: input },
          { path: `./${exportName}`, data: exported, format: 'gnu' },
        ]),
      };
    return undefined;
  });

  const hashed = new Map();
  const originalHash = crypto.createHash;
  crypto.createHash = (algorithm, ...rest) => {
    const hash = originalHash(algorithm, ...rest);
    const update = hash.update.bind(hash);
    hash.update = (data, ...more) => {
      if (algorithm === 'sha256' && data?.length) hashed.set(data.length, (hashed.get(data.length) ?? 0) + 1);
      update(data, ...more);
      return hash;
    };
    return hash;
  };
  syncBuiltinESMExports();
  let output;
  try {
    output = await runGovernedSandbox(executor, 'task', {
      broker,
      origin: 'shell',
      profile: { image },
      workspace,
      inputFiles: ['input.bin'],
      exportFiles: [exportName],
      command: ['/bin/produce'],
      inputClassification: 'public',
    });
    // A direct host classification is one receipt for one pass over the content.
    broker.classifyArtifact({ content: randomBytes(90_007), path: 'upload.bin', tenantId: 'tenant', origin: 'upload' });
  } finally {
    crypto.createHash = originalHash;
    syncBuiltinESMExports();
  }
  assert.equal(hashed.get(input.length), 1, 'a raw input is hashed once for its version check and its receipt');
  assert.equal(hashed.get(exported.length), 1, 'an export is hashed once, by the archive reader');
  assert.equal(hashed.get(90_007), 1, 'a classified artifact is hashed once');
  assert.ok(calls.some(args => args[0] === 'rm'));

  assert.equal(output.result.stdoutBase64, stdout.toString('base64'));
  assert.equal(output.result.stderrBase64, stderr.toString('base64'));
  assert.equal(output.result.stdout, stdout.toString('utf8'));
  assert.equal(output.stdout.payload.sha256, sha256(stdout));
  assert.equal(output.stdout.payload.bytes, stdout.length);
  assert.notEqual(output.stdout.payload.sha256, sha256(Buffer.from(stdout.toString('utf8'))));
  assert.equal(output.stderr.payload.sha256, sha256(stderr));
  assert.deepEqual(broker.verifyArtifact(output.stdout, stdout, 'tenant', executor), output.stdout.payload);
  assert.equal(output.artifacts[0].payload.path, exportName);
  assert.equal(output.artifacts[0].payload.sha256, sha256(exported));
  assert.equal(output.inputs[0].payload.sha256, sha256(input));

  // The reviewed copy verifies the stream receipts against the same bytes and writes the long path.
  const destination = join(directory(t), 'reviewed');
  const [written] = broker.writeReviewedArtifacts(
    executor,
    output,
    [{ path: exportName, sha256: sha256(exported) }],
    destination,
  );
  assert.ok(fs.readFileSync(written).equals(exported));
  assert.throws(
    () =>
      broker.writeReviewedArtifacts(
        executor,
        { ...output, result: { ...output.result, stdoutBase64: Buffer.from('other').toString('base64') } },
        [{ path: exportName, sha256: sha256(exported) }],
        join(destination, '..', 'tampered'),
      ),
    { code: 'ARTIFACT_INVALID' },
  );
  // A result recorded before the bytes were kept has only text; it still verifies when the text is the bytes.
  const { stderrBase64: _dropped, ...legacy } = output.result;
  assert.equal(
    broker.writeReviewedArtifacts(
      executor,
      { ...output, result: legacy },
      [{ path: exportName, sha256: sha256(exported) }],
      join(destination, '..', 'legacy'),
    ).length,
    1,
  );
});

test('a receipt for each of 256 inputs fits; the count and total size are coded limits', async t => {
  const { executor, broker } = host(t);
  const workspace = directory(t);
  const names = Array.from(
    { length: MAX_PATH_COUNT },
    (_, index) => `inputs/file-${String(index).padStart(3, '0')}.txt`,
  );
  fs.mkdirSync(join(workspace, 'inputs'));
  const receipts = names.map((name, index) => {
    const content = Buffer.from(`content ${index}`);
    fs.writeFileSync(join(workspace, name), content);
    return broker.classifyArtifact({
      content,
      path: name,
      tenantId: 'tenant',
      origin: 'upload',
      sensitivity: 'public',
    });
  });
  const options = {
    name: 'shell',
    executor,
    broker,
    profile: { image },
    workspace,
    tenantId: 'tenant',
    resourceId: 'workspace',
    origin: 'test',
    inputClassification: 'public',
    onResult: () => 'id',
  };
  const tool = createSandboxTool({ ...options, inputFiles: names, inputReceipts: receipts });
  assert.match(tool.metadata.configurationDigest, /^[a-f0-9]{64}$/);
  assert.equal(
    createSandboxTool({ ...options, inputFiles: names, inputReceipts: [...receipts].reverse() }).metadata
      .configurationDigest === tool.metadata.configurationDigest,
    false,
    'the digest still covers the receipts',
  );

  healthyDocker(t, args => (isCommand(args) ? { stdout: 'ok' } : undefined));
  const output = await runGovernedSandbox(executor, 'task', {
    broker,
    origin: 'shell',
    profile: { image },
    workspace,
    inputFiles: names,
    inputReceipts: receipts,
    inputClassification: 'public',
    command: ['/bin/true'],
  });
  assert.equal(output.inputs.length, MAX_PATH_COUNT);
  assert.equal(output.stdout.payload.lineage.length, MAX_PATH_COUNT);

  const limit = detail => error => {
    assert.equal(error.name, 'ExecutorError');
    assert.equal(error.code, 'ARTIFACT_RECEIPT_LIMIT');
    assert.equal(error.detail, detail);
    return true;
  };
  const tooMany = [...receipts, receipts[0]];
  assert.throws(
    () => createSandboxTool({ ...options, inputFiles: names, inputReceipts: tooMany }),
    limit('RECEIPT_COUNT'),
  );
  await assert.rejects(
    runGovernedSandbox(executor, 'task', {
      broker,
      origin: 'shell',
      profile: { image },
      workspace,
      inputFiles: names,
      inputReceipts: tooMany,
      command: ['/bin/true'],
    }),
    limit('RECEIPT_COUNT'),
  );
  // 80 receipts of about 124 KiB each pass one by one and exceed 8 MiB together.
  const heavy = Array.from({ length: 80 }, () => ({
    ...receipts[0],
    payload: { ...receipts[0].payload, lineage: Array.from({ length: 256 }, (_, i) => `${i}`.padEnd(480, 'l')) },
  }));
  assert.throws(
    () => createSandboxTool({ ...options, inputFiles: names, inputReceipts: heavy }),
    limit('RECEIPT_BYTES'),
  );
  // One malformed receipt is a validation failure, not a limit and not a TypeError.
  for (const bad of [null, 5, {}, { payload: null, signature: 'x' }])
    assert.throws(() => createSandboxTool({ ...options, inputFiles: names, inputReceipts: [bad] }), {
      name: 'ExecutorError',
      code: 'ARTIFACT_INVALID',
    });
});

test('a failed cleanup keeps the run error as its cause, and a refused create is not a cleanup failure', async t => {
  const workspace = directory(t);
  fs.writeFileSync(join(workspace, 'input.txt'), 'input');
  const secret = '/private/host/path/secret-token';
  const run = () =>
    runDockerSandbox({ profile: { image }, workspace, inputFiles: ['input.txt'], command: ['/bin/true'] });
  let reply;
  const calls = healthyDocker(t, args => reply(args));

  // The command fails and the container cannot be removed: both facts reach the caller.
  reply = args => {
    if (args[0] === 'start') return { code: 1, stderr: `Error response from daemon: permission denied ${secret}` };
    if (args[0] === 'rm') return { code: 1, stderr: `Cannot connect to the Docker daemon at ${secret}` };
    return undefined;
  };
  await assert.rejects(run(), error => {
    assert.equal(error.name, 'ExecutorError');
    assert.equal(error.code, 'SANDBOX_CLEANUP_FAILED');
    assert.equal(error.detail, 'CONTAINER_LEFT');
    assert.match(error.message, /remove container agent-guard-[a-f0-9-]{36}/);
    assert.equal(error.cause.code, 'SANDBOX_DOCKER_FAILED');
    assert.equal(error.cause.detail, 'PERMISSION_DENIED');
    assert.match(error.cause.message, /Docker start failed/);
    assert.equal(`${error.message} ${error.cause.message} ${JSON.stringify(error)}`.includes(secret), false);
    return true;
  });

  // Docker refused to create the container: there is nothing to remove, so the refusal is the error.
  calls.length = 0;
  reply = args => {
    if (args[0] === 'create') return { code: 1, stderr: `Error response from daemon: No such image: ${secret}` };
    if (args[0] === 'rm') return { code: 1, stderr: 'Error response from daemon: something else went wrong' };
    return undefined;
  };
  await assert.rejects(run(), error => {
    assert.equal(error.code, 'SANDBOX_DOCKER_FAILED');
    assert.equal(error.detail, 'IMAGE_NOT_FOUND');
    assert.match(error.message, /Docker create failed/);
    assert.equal(error.message.includes(secret), false);
    return true;
  });
  assert.equal(
    calls.some(args => args[0] === 'start'),
    false,
  );

  // A container that is already gone is a finished cleanup.
  reply = args => {
    if (isCommand(args)) return { code: 3, stdout: 'partial' };
    if (args[0] === 'rm') return { code: 1, stderr: 'Error response from daemon: No such container: agent-guard-x' };
    return undefined;
  };
  assert.equal((await run()).exitCode, 3);

  // The run succeeded but the container is left behind: fail closed, with no cause to report.
  reply = args => (args[0] === 'rm' ? { code: 1, stderr: 'unexpected' } : undefined);
  await assert.rejects(run(), error => {
    assert.equal(error.code, 'SANDBOX_CLEANUP_FAILED');
    assert.equal(error.detail, 'CONTAINER_LEFT');
    assert.equal(error.cause, undefined);
    return true;
  });

  // An unreadable daemon answer and a missing CLI are coded too.
  reply = args => (args[0] === 'info' ? { stdout: 'not json' } : undefined);
  await assert.rejects(run(), error => error.code === 'SANDBOX_DOCKER_FAILED' && error.detail === 'RESPONSE_INVALID');
  reply = args => (args[0] === 'version' ? { stdout: 'windows\n' } : undefined);
  await assert.rejects(
    run(),
    error => error.code === 'SANDBOX_HOST_UNSUPPORTED' && error.detail === 'DAEMON_NOT_LINUX',
  );
});

test('an interrupted create still removes the container, and the abort stays the reported cause', async t => {
  const workspace = directory(t);
  let controller = new AbortController();
  let removalFails = false;
  const calls = healthyDocker(t, args => {
    // The CLI is stopped mid-create: the daemon may have created the container anyway.
    if (args[0] === 'create') controller.abort();
    if (args[0] === 'rm' && removalFails) return { code: 1, stderr: 'unexpected' };
    return undefined;
  });
  const run = signal =>
    runDockerSandbox({ profile: { image }, workspace, inputFiles: [], command: ['/bin/true'], signal });
  await assert.rejects(run(controller.signal), { name: 'ExecutorError', code: 'SANDBOX_ABORTED' });
  assert.equal(calls.filter(args => args[0] === 'rm').length, 1, 'removal is attempted when creation is uncertain');
  assert.equal(
    calls.some(args => args[0] === 'start'),
    false,
  );

  removalFails = true;
  controller = new AbortController();
  await assert.rejects(run(controller.signal), error => {
    assert.equal(error.code, 'SANDBOX_CLEANUP_FAILED');
    assert.equal(error.detail, 'CONTAINER_LEFT');
    assert.equal(error.cause.code, 'SANDBOX_ABORTED');
    return true;
  });

  // Already aborted: nothing is spawned.
  calls.length = 0;
  await assert.rejects(run(AbortSignal.abort()), { code: 'SANDBOX_ABORTED' });
  assert.equal(calls.length, 0);
});

test('a missing Docker CLI is a coded failure with the spawn error as its cause', async t => {
  const workspace = directory(t);
  const path = process.env.PATH,
    dockerHost = process.env.DOCKER_HOST;
  process.env.PATH = join(workspace, 'no-such-bin');
  delete process.env.DOCKER_HOST;
  t.after(() => {
    process.env.PATH = path;
    if (dockerHost !== undefined) process.env.DOCKER_HOST = dockerHost;
  });
  await assert.rejects(
    runDockerSandbox({ profile: { image }, workspace, inputFiles: [], command: ['/bin/true'] }),
    error => {
      assert.equal(error.name, 'ExecutorError');
      assert.equal(error.code, 'SANDBOX_DOCKER_FAILED');
      assert.equal(error.detail, 'CLI_UNAVAILABLE');
      assert.equal(error.cause.code, 'ENOENT');
      return true;
    },
  );
  for (const [profile, command] of [
    [{ image: 'alpine:latest' }, ['/bin/true']],
    [{ image, privileged: true }, ['/bin/true']],
    [null, ['/bin/true']],
  ])
    await assert.rejects(runDockerSandbox({ profile, workspace, inputFiles: [], command }), {
      name: 'ExecutorError',
      code: 'SANDBOX_PROFILE_INVALID',
    });
  await assert.rejects(runDockerSandbox({ profile: { image }, workspace, inputFiles: [], command: [] }), {
    code: 'SANDBOX_ARGUMENT_INVALID',
  });
});

test('a missing sandbox input is reported as missing before any container is created', { skip: !posix }, async t => {
  const workspace = directory(t);
  const calls = healthyDocker(t);
  await assert.rejects(
    runDockerSandbox({ profile: { image }, workspace, inputFiles: ['absent.txt'], command: ['/bin/true'] }),
    error => {
      assert.equal(error.name, 'ExecutorError');
      assert.equal(error.code, 'WORKSPACE_INPUT_MISSING');
      return true;
    },
  );
  assert.equal(
    calls.some(args => args[0] === 'create' || args[0] === 'rm'),
    false,
  );
  await assert.rejects(
    runDockerSandbox({
      profile: { image },
      workspace: join(workspace, 'absent'),
      inputFiles: [],
      command: ['/bin/true'],
    }),
    error => error.code === 'SANDBOX_ARGUMENT_INVALID' && error.detail === 'WORKSPACE_UNAVAILABLE',
  );
});

test('workspace input failures name what happened: missing, symlink, hard link, size', { skip: !posix }, t => {
  const root = directory(t);
  fs.mkdirSync(join(root, 'nested'));
  fs.writeFileSync(join(root, 'nested', 'item'), 'selected');
  fs.writeFileSync(join(root, 'target'), 'outside');
  fs.symlinkSync(join(root, 'target'), join(root, 'link'));
  fs.symlinkSync(join(root, 'nowhere'), join(root, 'dangling'));
  fs.symlinkSync(join(root, 'nested'), join(root, 'linked-directory'), 'dir');
  const failure = (name, maximum = 64) => {
    try {
      readWorkspaceInput(root, name, maximum);
    } catch (error) {
      assert.equal(error.name, 'ExecutorError');
      // Like the Windows reader: no OS error text, which would carry the private host path.
      assert.equal(error.cause, undefined);
      assert.equal(`${error.message} ${JSON.stringify(error)}`.includes(root), false);
      return [error.code, error.detail];
    }
    return assert.fail(`${name} must be refused`);
  };
  assert.deepEqual(failure('absent'), ['WORKSPACE_INPUT_MISSING', undefined]);
  assert.deepEqual(failure('nested/absent'), ['WORKSPACE_INPUT_MISSING', undefined]);
  assert.deepEqual(failure('absent/item'), ['WORKSPACE_INPUT_MISSING', undefined]);
  assert.equal(failure('link')[0], 'WORKSPACE_INPUT_UNSAFE');
  assert.equal(failure('dangling')[0], 'WORKSPACE_INPUT_UNSAFE');
  assert.equal(failure('linked-directory/item')[0], 'WORKSPACE_INPUT_UNSAFE');
  assert.deepEqual(failure('nested/item', 7), ['WORKSPACE_INPUT_LIMIT', undefined]);
  assert.deepEqual(failure('nested'), ['WORKSPACE_INPUT_UNSAFE', 'INPUT_NOT_REGULAR']);
  fs.linkSync(join(root, 'nested', 'item'), join(root, 'alias'));
  assert.deepEqual(failure('nested/item'), ['WORKSPACE_INPUT_UNSAFE', 'INPUT_HARD_LINK']);
  assert.deepEqual(failure('../escape'), ['WORKSPACE_INPUT_INVALID', undefined]);
  assert.deepEqual(failure(5), ['WORKSPACE_INPUT_INVALID', undefined]);
});

test('reviewed exports report a used destination and a malformed review with codes', t => {
  const dir = directory(t);
  const files = readSandboxArchive(tar([{ path: './answer.txt', data: 'safe' }]), ['answer.txt'], 100);
  const approved = files.map(({ path, sha256: digest }) => ({ path, sha256: digest }));
  writeReviewedExports({ exports: files }, approved, join(dir, 'reviewed'));
  assert.throws(
    () => writeReviewedExports({ exports: files }, approved, join(dir, 'reviewed')),
    error => error.code === 'SANDBOX_EXPORT_DESTINATION_UNAVAILABLE' && error.detail === 'EEXIST',
  );
  for (const [result, selection, detail] of [
    [null, approved, 'REVIEW_SHAPE'],
    [{ exports: files }, [null], 'REVIEW_SHAPE'],
    [{ exports: files }, [{ path: 'answer.txt', sha256: '0'.repeat(64) }], 'REVIEW_HASH'],
    [
      { exports: [{ ...files[0], contentBase64: Buffer.from('evil').toString('base64') }] },
      approved,
      'REVIEW_INTEGRITY',
    ],
  ])
    assert.throws(
      () => writeReviewedExports(result, selection, join(dir, 'other')),
      error => error.code === 'SANDBOX_EXPORT_REVIEW_INVALID' && error.detail === detail,
      detail,
    );
  assert.equal(fs.existsSync(join(dir, 'other')), false);
});

test('an error from the sandbox tool host callbacks is a tool failure, never an executor decision', async t => {
  const { executor, broker } = host(t);
  const workspace = directory(t);
  const calls = healthyDocker(t, args => (isCommand(args) ? { stdout: 'ok' } : undefined));
  let clockFails = false;
  const failingClock = new ArtifactBroker({
    key: randomBytes(32),
    keyId: 'failing-clock',
    clock: () => {
      if (clockFails) throw new GuardError('TASK_REVOKED');
      return Date.now();
    },
  });
  t.after(() => failingClock.close());
  let index = 0;
  /** One prepared and executed sandbox call with its own tool and task; returns what execute() threw. */
  const call = async (onResult, signer = broker) => {
    const name = `shell-${index++}`;
    const tool = createSandboxTool({
      name,
      executor,
      broker: signer,
      profile: { image },
      workspace,
      inputFiles: [],
      tenantId: 'tenant',
      resourceId: 'workspace',
      origin: 'test',
      inputClassification: 'public',
      requiresApproval: false,
      onResult,
    });
    executor.approveTool(name, executor.registerTool(tool));
    executor.createTask({
      id: name,
      principalId: 'operator',
      tenantId: 'tenant',
      grants: [{ tool: name, resources: ['workspace'] }],
      budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
    });
    const action = await executor.prepare(name, { tool: name, args: { command: ['/bin/true'] } });
    let error, value;
    try {
      value = await executor.execute(name, action.id);
    } catch (caught) {
      error = caught;
    }
    return { error, value, taskId: name, actionId: action.id };
  };

  // The codes the sandbox tool may raise itself earn nothing when the host's result sink throws them.
  for (const thrown of [
    new GuardError('TASK_REVOKED'),
    new GuardError('TOOL_CHANGED'),
    new GuardError('EXECUTION_ABORTED'),
    new ExecutorError('SANDBOX_FAILED'),
    new ExecutorError('ARTIFACT_INVALID'),
  ]) {
    for (const onResult of [
      () => {
        throw thrown;
      },
      () => Promise.reject(thrown),
    ]) {
      const { error, taskId, actionId } = await call(onResult);
      assert.deepEqual([error.name, error.code, error.detail], ['GuardError', 'TOOL_FAILED', thrown.code]);
      // The command ran, so the outcome is unknown; and no task was revoked.
      assert.equal(executor.execution(taskId, actionId).status, 'UNKNOWN');
      assert.equal(executor.assertProvenance(taskId).id, taskId);
    }
  }
  const plain = await call(() => {
    throw new Error('storage down');
  });
  assert.deepEqual([plain.error.code, plain.error.detail], ['TOOL_FAILED', undefined]);
  // The broker's clock is host code too.
  clockFails = true;
  const clock = await call(() => 'id', failingClock);
  clockFails = false;
  assert.deepEqual([clock.error.code, clock.error.detail], ['TOOL_FAILED', 'TASK_REVOKED']);
  // The tool's own refusal, raised by the tool, keeps its code: a result ID must be a short string.
  const own = await call(() => '');
  assert.deepEqual([own.error.name, own.error.code], ['ExecutorError', 'ARTIFACT_INVALID']);
  // And a sink that works returns the result.
  const done = await call(() => 'result-1');
  assert.equal(done.error, undefined);
  assert.equal(done.value.resultId, 'result-1');
  assert.equal(calls.filter(isCommand).length, index, 'every call ran its command');
});
