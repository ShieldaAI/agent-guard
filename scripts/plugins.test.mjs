// The Agent Guard Check plugin folder and its listings: every manifest agrees, every pinned
// version moves with the package, and the folder meets the rules each directory checks on submission
// (Anthropic's plugin directory, OpenAI's plugin portal, Antigravity's marketplace, the MCP Registry).

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { archives, PLUGIN } from './pack-plugins.mjs';
import {
  npxArgs,
  npxCli,
  PACKAGE,
  projectRoot,
  VERSION as LAUNCHER_VERSION,
} from '../plugins/agent-guard-check/scripts/start-mcp-server.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DIR = join(ROOT, PLUGIN);
const read = path => readFileSync(join(ROOT, path), 'utf8');
const json = path => JSON.parse(read(path));
const version = json('packages/check/package.json').version;
const repoPath = resolve('/work/repo');

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}
const files = walk(DIR).map(path => relative(DIR, path).split(sep).join('/'));

const claude = json(`${PLUGIN}/.claude-plugin/plugin.json`);
const portable = json(`${PLUGIN}/plugin.json`);
const openai = portable.extensions['com.openai'];
const antigravity = json(`${PLUGIN}/.antigravity-plugin/plugin.json`);
const skillText = read(`${PLUGIN}/skills/agent-guard-check/SKILL.md`);
const skill = parseYaml(skillText.split('---')[1]);
const server = json('packages/check/server.json');

function pngSize(path) {
  const bytes = readFileSync(join(DIR, path));
  assert.equal(bytes.subarray(1, 4).toString('latin1'), 'PNG', `${path} is not a PNG`);
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

function contrast(hex, against) {
  const lum = value => {
    const [r, g, b] = [1, 3, 5].map(i => parseInt(value.slice(i, i + 2), 16) / 255);
    const lin = c => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  };
  const [a, b] = [lum(hex), lum(against)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
}

test('every manifest names the same plugin, version and description', () => {
  for (const manifest of [claude, portable, antigravity]) {
    assert.equal(manifest.name, 'agent-guard-check');
    assert.equal(manifest.version, version, 'plugin versions move with @shieldaai/agent-guard-check');
    assert.equal(manifest.description, claude.description);
    assert.equal(manifest.license, 'Apache-2.0');
  }
  assert.equal(claude.displayName, 'Agent Guard Check');
  assert.equal(antigravity.displayName, claude.displayName);
  assert.equal(openai.interface.displayName, claude.displayName);
});

test('every pinned scanner version matches the package', () => {
  assert.equal(LAUNCHER_VERSION, version, 'scripts/start-mcp-server.mjs VERSION');
  assert.equal(PACKAGE, '@shieldaai/agent-guard-check');
  for (const path of [`${PLUGIN}/skills/agent-guard-check/SKILL.md`, `${PLUGIN}/README.md`]) {
    const pins = [...read(path).matchAll(/agent-guard-check@(\d+\.\d+\.\d+[\w.-]*)/g)].map(match => match[1]);
    assert.ok(pins.length > 0, `${path} pins no version`);
    for (const pin of pins) assert.equal(pin, version, `${path} pins ${pin}`);
  }
  assert.equal(server.version, version);
  assert.equal(server.packages[0].version, version);
});

test('the marketplaces list the plugin folder', () => {
  const claudeMarket = json('.claude-plugin/marketplace.json');
  assert.equal(claudeMarket.plugins[0].name, claude.name);
  assert.equal(claudeMarket.plugins[0].source, `./${PLUGIN}`);
  assert.equal(claudeMarket.plugins[0].description, claude.description);
  const codexMarket = json('.agents/plugins/marketplace.json');
  assert.equal(codexMarket.name, claudeMarket.name);
  assert.equal(codexMarket.plugins[0].name, claude.name);
  assert.deepEqual(codexMarket.plugins[0].source, { source: 'local', path: `./${PLUGIN}` });
});

test('Claude directory: layout, size and file rules', () => {
  assert.match(claude.name, /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/);
  for (const key of ['description', 'author', 'version', 'license', 'homepage', 'repository'])
    assert.ok(claude[key], key);
  assert.ok(existsSync(join(DIR, claude.icon)), 'icon file exists');
  for (const key of ['documentationUrl', 'supportUrl', 'privacyPolicyUrl', 'termsOfServiceUrl'])
    assert.match(claude[key], /^https:\/\//, key);
  // README of at least 40 words outside code blocks, and a license in the folder.
  const prose = read(`${PLUGIN}/README.md`).replace(/```[\s\S]*?```/g, ' ');
  assert.ok(prose.split(/\s+/).filter(Boolean).length >= 40);
  assert.ok(existsSync(join(DIR, 'LICENSE')));
  assert.ok(files.length <= 512);
  for (const file of files) {
    const path = join(DIR, file);
    assert.ok(!lstatSync(path).isSymbolicLink(), `${file} is a link`);
    assert.ok(!/(^|\/)(\.DS_Store|Thumbs\.db|desktop\.ini|__MACOSX)$/.test(file), `${file} is a system file`);
    assert.ok(!/(^|\/)\.npmrc$|bunfig\.toml$|uv\.toml$/.test(file), `${file} sets a package source`);
    assert.ok(/\.(png|svg)$/.test(file) || statSync(path).size < 256 * 1024, `${file} is over 256 KiB`);
    assert.ok(/^[A-Za-z0-9._/-]+$/.test(file), `${file} has a name some systems refuse`);
  }
  // A top-level bin/ keeps claude.ai and Cowork from installing the plugin.
  assert.ok(!files.some(file => file.startsWith('bin/')));
  // No lockfile install and no package manifest: nothing installs when the plugin does.
  assert.ok(!files.includes('package.json') && !files.includes('package-lock.json'));
});

test('MCP configs start the bundled launcher by a path inside the plugin', () => {
  const configs = {
    '.mcp.json': '${CLAUDE_PLUGIN_ROOT}',
    'mcp.json': '${PLUGIN_ROOT}',
    'mcp_config.json': '${PLUGIN_ROOT}',
  };
  for (const [file, variable] of Object.entries(configs)) {
    const servers = json(`${PLUGIN}/${file}`).mcpServers;
    assert.deepEqual(Object.keys(servers), ['agent-guard-check'], file);
    const entry = servers['agent-guard-check'];
    assert.equal(entry.command, 'node', file);
    assert.deepEqual(entry.args, [`${variable}/scripts/start-mcp-server.mjs`], file);
    // No cwd: the host starts the server in the open project, which is what it checks.
    assert.equal(entry.cwd, undefined, file);
    assert.equal(entry.env, undefined, file);
  }
  assert.equal(json(`${PLUGIN}/mcp.json`).mcpServers['agent-guard-check'].type, 'stdio');
  assert.ok(existsSync(join(DIR, 'scripts/start-mcp-server.mjs')));
});

test('skill: front matter every host accepts', () => {
  assert.equal(skill.name, 'agent-guard-check');
  assert.match(skill.name, /^[a-z0-9-]{1,64}$/);
  assert.equal(typeof skill.description, 'string');
  assert.ok(skill.description.length >= 1 && skill.description.length <= 1024);
  // OpenAI asks for provider-neutral skills: no instructions addressed to one vendor's model.
  assert.doesNotMatch(skillText, /\b(Claude|ChatGPT|Gemini),? (should|must|will)\b/);
});

test('OpenAI portal: interface limits, icons and colors', () => {
  const ui = openai.interface;
  assert.equal(openai.requires_local_executor, true);
  assert.ok(ui.displayName.length <= 30);
  assert.ok(ui.shortDescription.length <= 30);
  assert.ok(ui.longDescription.length <= 4000);
  assert.ok(ui.developerName.length <= 80);
  assert.ok(Array.isArray(ui.capabilities) && ui.capabilities.length <= 20);
  assert.ok(ui.defaultPrompt.length <= 3 && new Set(ui.defaultPrompt).size === ui.defaultPrompt.length);
  for (const prompt of ui.defaultPrompt) assert.ok(prompt.length <= 128 && !prompt.includes('@'), prompt);
  for (const key of ['websiteURL', 'supportURL', 'privacyPolicyURL', 'termsOfServiceURL'])
    assert.match(ui[key], /^https:\/\/.{1,1000}$/, key);
  assert.match(ui.brandColor, /^#[0-9A-F]{6}$/i);
  assert.ok(contrast(ui.brandColor, '#FFFFFF') >= 2, 'brandColor contrast against white');
  for (const key of ['composerIcon', 'logo']) {
    assert.match(ui[key], /^\.\//);
    const { width, height } = pngSize(ui[key]);
    assert.equal(width, height, `${key} is square`);
    assert.ok(width >= 48 && width <= 4096, `${key} size`);
  }
  // Lifecycle hooks and app references cannot be submitted.
  assert.ok(!files.some(file => file.startsWith('hooks/')) && !files.includes('.app.json'));
  assert.equal(openai.hooks, undefined);
  assert.equal(openai.apps, undefined);
});

test('OpenAI archives: skills-only leaves out the MCP server, local-MCP adds it', () => {
  const [skills, local] = archives();
  assert.equal(skills.kind, 'openai-skills');
  assert.ok(skills.files.includes('plugin.json') && skills.files.includes('skills/agent-guard-check/SKILL.md'));
  assert.ok(!skills.files.some(file => /mcp|^scripts\//.test(file)), 'no MCP config or launcher');
  assert.ok(!skills.files.some(file => file.startsWith('.')), 'no other hosts’ manifests');
  assert.deepEqual(
    local.files.filter(file => !skills.files.includes(file)),
    ['mcp.json', 'scripts/start-mcp-server.mjs'],
  );
  for (const archive of [skills, local])
    for (const file of [openai.interface.logo, openai.interface.composerIcon])
      assert.ok(archive.files.includes(file.slice(2)), `${archive.kind} has ${file}`);
});

test('Antigravity marketplace: required fields and limits', () => {
  assert.match(antigravity.name, /^[a-z0-9-]+$/);
  for (const key of ['displayName', 'description', 'version', 'logo', 'suggestedPrompts', 'author'])
    assert.ok(antigravity[key], key);
  assert.ok(antigravity.description.length >= 120 && antigravity.description.length <= 160);
  assert.ok(antigravity.suggestedPrompts.length <= 3);
  assert.deepEqual(antigravity.suggestedPrompts, openai.interface.defaultPrompt);
  assert.ok(existsSync(join(DIR, antigravity.logo)));
  assert.match(antigravity.author.url, /^https:\/\//);
});

test('MCP Registry: server.json matches the npm package', () => {
  const pkg = json('packages/check/package.json');
  assert.equal(server.name, pkg.mcpName, 'mcpName proves npm ownership');
  assert.match(server.name, /^io\.github\.ShieldaAI\/[a-zA-Z0-9._-]+$/);
  assert.ok(server.description.length <= 100);
  const [entry] = server.packages;
  assert.equal(entry.registryType, 'npm');
  assert.equal(entry.registryBaseUrl, 'https://registry.npmjs.org');
  assert.equal(entry.identifier, pkg.name);
  assert.equal(entry.transport.type, 'stdio');
  assert.equal(entry.packageArguments[0].value, '--mcp', '--mcp must be the first argument');
  assert.ok(!pkg.files.includes('server.json'), 'server.json is registry metadata, not package content');
});

test('launcher: picks the open project and refuses to scan itself', () => {
  const plugin = DIR;
  const repo = resolve('/work/repo');
  assert.equal(
    projectRoot({ argv: [repo], env: { CLAUDE_PROJECT_DIR: resolve('/x') }, cwd: resolve('/y'), plugin }),
    repo,
  );
  assert.equal(projectRoot({ env: { CLAUDE_PROJECT_DIR: repo }, cwd: resolve('/y'), plugin }), repo);
  assert.equal(projectRoot({ env: {}, cwd: repo, plugin }), repo);
  assert.equal(projectRoot({ env: {}, cwd: resolve('/work'), argv: ['repo'], plugin }), repo);
  // A host that starts the server in the plugin folder did not say which project is open.
  assert.equal(projectRoot({ env: {}, cwd: plugin, plugin }), undefined);
  assert.equal(projectRoot({ env: {}, cwd: join(plugin, 'scripts'), plugin }), undefined);
  // A project that merely contains the plugin (this repository) is a project.
  assert.equal(projectRoot({ env: {}, cwd: ROOT, plugin }), resolve(ROOT));
});

test('launcher: runs npm\u2019s own npx with the pinned package, never PATH', () => {
  const cellar = resolve('/opt/homebrew/Cellar/node/26/bin');
  const linked = resolve('/opt/homebrew/lib/node_modules/npm/bin/npx-cli.js');
  const fs = present => ({
    exists: path => present.includes(path),
    realpath: path => {
      if (path === join(cellar, 'npx')) return linked;
      throw new Error('ENOENT');
    },
  });
  assert.equal(npxCli(join(cellar, 'node'), fs([linked])), linked);
  const lib = resolve('/usr/local/lib/node_modules/npm/bin/npx-cli.js');
  assert.equal(npxCli(resolve('/usr/local/bin/node'), fs([lib])), lib);
  const windows = resolve('/nodejs/node_modules/npm/bin/npx-cli.js');
  assert.equal(npxCli(resolve('/nodejs/node.exe'), fs([windows])), windows);
  assert.equal(npxCli(resolve('/nowhere/bin/node'), fs([])), undefined);
  // A sibling npx that is some other program is not used.
  const other = { exists: () => true, realpath: () => resolve('/tmp/evil/npx') };
  assert.notEqual(npxCli(resolve('/opt/x/bin/node'), other), resolve('/tmp/evil/npx'));
  assert.deepEqual(npxArgs('npx-cli.js', repoPath), [
    'npx-cli.js',
    '--yes',
    `--package=@shieldaai/agent-guard-check@${version}`,
    '--',
    'agent-guard-check-mcp',
    repoPath,
  ]);
});
