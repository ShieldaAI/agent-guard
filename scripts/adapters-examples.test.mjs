import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const run = (...args) => execFileSync(process.execPath, args, { cwd: root, encoding: 'utf8' });

test('model-adapters example: every provider format gets the same three answers', () => {
  const lines = run('examples/model-adapters.mjs').trim().split('\n');
  assert.deepEqual(
    lines.map(line => line.slice(0, 24).trim()),
    ['Anthropic Messages', 'OpenAI Responses', 'OpenAI Chat Completions', 'Google Gemini', 'Amazon Bedrock Converse'],
  );
  for (const line of lines)
    assert.equal(line.slice(25), 'ok | denied GRANT_DENIED | waiting_for_approval | after approval: ok');
});

test('guarded MCP server example: a real MCP client goes through the guard', () => {
  assert.equal(
    run('examples/mcp-guarded-server.mjs', '--self-test'),
    [
      'tools: ticket_read, ticket_close',
      'ticket_read {"id":"42"} -> ok',
      'ticket_read {"id":"7"} -> denied GRANT_DENIED',
      `ticket_read {"id":"42; DROP TABLE"} -> refused by the MCP SDK's own schema check`,
      'ticket_close {"id":"42"} -> waiting_for_approval',
      'approved by alice -> ok; ticket 42 is closed',
      'decisions logged: 6',
      '',
    ].join('\n'),
  );
});
