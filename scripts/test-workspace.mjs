import { spawn } from 'node:child_process';

// Keep shell-expanded paths (or literal globs on Windows) exactly as supplied.
// Only test-file scheduling changes; tests retain their own concurrency and limits.
const files = process.argv.slice(2);
if (files.length === 0) {
  process.stderr.write('WORKSPACE_TEST_FILES_REQUIRED\n');
  process.exitCode = 1;
} else {
  const child = spawn(
    process.execPath,
    ['--test', ...(process.platform === 'win32' ? ['--test-concurrency=1'] : []), ...files],
    { stdio: 'inherit' },
  );
  let interrupted;
  const forwardInterrupt = () => {
    interrupted ??= 'SIGINT';
    child.kill('SIGINT');
  };
  const forwardTerminate = () => {
    interrupted ??= 'SIGTERM';
    child.kill('SIGTERM');
  };
  process.once('SIGINT', forwardInterrupt);
  process.once('SIGTERM', forwardTerminate);
  child.once('error', () => {
    process.stderr.write('WORKSPACE_TEST_RUNNER_START_FAILED\n');
    process.exitCode = 1;
  });
  child.once('close', (code, signal) => {
    process.removeListener('SIGINT', forwardInterrupt);
    process.removeListener('SIGTERM', forwardTerminate);
    const terminalSignal = interrupted ?? signal;
    if (terminalSignal) {
      try {
        process.kill(process.pid, terminalSignal);
      } catch {
        process.exitCode = 1;
      }
    } else process.exitCode = code ?? 1;
  });
}
