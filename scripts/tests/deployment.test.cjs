const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const { test } = require('node:test')

const root = path.resolve(__dirname, '../..')
const read = filename => fs.readFileSync(path.join(root, filename), 'utf8')

test('Dockerfile installs the release overlays at the native module paths', () => {
  const dockerfile = read('ldap-overleaf-sl/Dockerfile')
  assert.match(dockerfile, /^FROM sharelatex\/sharelatex:5\.5\.8$/m)
  assert.match(dockerfile, /COPY sharelatex\/router\.js\s+\/overleaf\/services\/web\/app\/src\/router\.mjs/)
  assert.match(dockerfile, /COPY sharelatex\/ContactController\.js\s+\/overleaf\/services\/web\/app\/src\/Features\/Contacts\/ContactController\.mjs/)
  assert.doesNotMatch(dockerfile, /^RUN .*overleaf\/overleaf\/main/m)
  assert.doesNotMatch(dockerfile, /^COPY .*navbar-marketing-bootstrap-5\.pug/m)
  assert.doesNotMatch(dockerfile, /verify-repo=none|^ENV PATH=.*2023/m)
  for (const match of dockerfile.matchAll(/^COPY\s+(\S+)/gm)) {
    assert.ok(fs.existsSync(path.join(root, 'ldap-overleaf-sl', match[1])), match[1])
  }
})

test('maintenance scripts have valid shell syntax', () => {
  const router = read('ldap-overleaf-sl/sharelatex/router.js')
  assert.match(router, /^export default \{ initialize, rateLimiters \}/m)
  assert.doesNotMatch(router, /module\.exports\s*=/)
  const syntax = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: router, encoding: 'utf8' })
  assert.equal(syntax.status, 0, syntax.stderr)
  const result = spawnSync('bash', ['-n', 'scripts/extract_files.sh', 'scripts/apply_diffs.sh', 'scripts/make_diffs.sh'], { cwd: root, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const extraction = read('scripts/extract_files.sh')
  assert.match(extraction, /docker create/)
  assert.match(extraction, /trap .*EXIT/)
  assert.doesNotMatch(extraction, /docker run|sleep /)
})

test('every generated patch reproduces its deployed overlay', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'overleaf-patch-test-'))
  try {
    const result = spawnSync('bash', ['scripts/apply_diffs.sh'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATCHED_DIR: temporary },
    })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    for (const filename of fs.readdirSync(path.join(root, 'ldap-overleaf-sl/sharelatex_diff'))) {
      if (!filename.endsWith('.diff')) continue
      const target = filename.slice(0, -5)
      assert.equal(fs.readFileSync(path.join(temporary, target), 'utf8'), read(`ldap-overleaf-sl/sharelatex/${target}`), target)
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true })
  }
})

test('patch application rejects missing baselines instead of silently succeeding', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'overleaf-missing-test-'))
  try {
    const result = spawnSync('bash', ['scripts/apply_diffs.sh'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, ORI_DIR: temporary, PATCHED_DIR: path.join(temporary, 'patched') },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /No original file/)
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true })
  }
})

test('canonical Compose carries generic configuration and private database services', () => {
  const result = spawnSync('docker', ['compose', '--env-file', '.env.example', '-f', 'docker-compose.yml', 'config', '--format', 'json'], {
    cwd: root, encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
  const compose = JSON.parse(result.stdout)
  const { sharelatex, traefik, mongo, mongoinit, redis } = compose.services
  assert.equal(sharelatex.image, 'ldap-overleaf-sl:5.5.8')
  assert.equal(sharelatex.environment.ALLOW_EMAIL_LOGIN, 'true')
  assert.equal(sharelatex.environment.ALLOW_LDAP_LOGIN, 'false')
  assert.equal(sharelatex.environment.OAUTH2_ENABLED, 'false')
  assert.equal(sharelatex.environment.LDAP_SERVER, '')
  assert.equal(mongo.image, 'mongo:6.0')
  assert.equal(mongoinit.image, mongo.image)
  assert.equal(mongo.ports, undefined)
  assert.equal(mongo.labels, undefined)
  assert.ok(mongoinit.entrypoint.at(-1).includes('rs.status()'))
  assert.deepEqual(redis.command, ['redis-server', '--appendonly', 'yes'])
  assert.ok(!traefik.command.includes('--api.insecure=true'))
  assert.ok(!traefik.ports.some(port => port.target === 8080))
  assert.equal(sharelatex.depends_on.mongoinit.condition, 'service_completed_successfully')
  assert.doesNotMatch(read('docker-compose.yml'), /uibk|ifi-auth/)
  for (const filename of ['docker-compose.certbot.yml', 'docker-compose.traefik.yml', 'docker-compose.uibk.yml', 'docker-compose.uibk-oauth.yml']) {
    assert.ok(!fs.existsSync(path.join(root, filename)))
    assert.ok(!read('README.md').includes(filename))
  }
})

test('site configuration is ignored while the environment example remains trackable', () => {
  for (const filename of ['.env']) {
    const ignored = spawnSync('git', ['check-ignore', '--no-index', filename], { cwd: root, encoding: 'utf8' })
    assert.equal(ignored.status, 0, filename)
  }
  assert.equal(spawnSync('git', ['check-ignore', '--no-index', '.env.example'], { cwd: root }).status, 1)
  assert.equal(spawnSync('git', ['ls-files', '.env'], { cwd: root, encoding: 'utf8' }).stdout, '')
})