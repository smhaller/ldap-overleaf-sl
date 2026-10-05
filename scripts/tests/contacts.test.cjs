const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { spawnSync } = require('node:child_process')
const { test } = require('node:test')

const root = path.resolve(__dirname, '../..')
const overlay = path.join(root, 'ldap-overleaf-sl/sharelatex/ContactController.js')
const original = path.join(root, 'ldap-overleaf-sl/sharelatex_ori/ContactController.js')
const diff = path.join(root, 'ldap-overleaf-sl/sharelatex_diff/ContactController.js.diff')
const plain = value => JSON.parse(JSON.stringify(value))

function deferred() {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}

function fixture(options = {}) {
  const calls = []
  const errors = []
  const locals = options.locals || [
    { _id: 'second', email: 'Second@example.org', first_name: 'Second' },
    { _id: 'holding', email: 'mistyped@example.org', holdingAccount: true },
    { _id: 'first', email: 'first@example.org', last_name: 'Local' },
  ]
  const dependencies = {
    '../Authentication/SessionManager.js': {
      getLoggedInUserId(session) {
        calls.push(['session', session])
        return session.userId
      },
    },
    './ContactManager.js': { promises: {
      async getContactIds(...args) {
        calls.push(['ids', ...args])
        if (options.localError) throw options.localError
        return ['first', 'second', 'holding']
      },
    } },
    '../User/UserGetter.js': { promises: {
      async getUsers(...args) {
        calls.push(['users', ...args])
        return locals.slice()
      },
    } },
    '../../infrastructure/Modules.js': { promises: { hooks: {
      async fire(...args) {
        calls.push(['hooks', ...args])
        if (options.hookError) throw options.hookError
        return options.additionalContacts
      },
    } } },
    '@overleaf/promise-utils': {
      expressify: handler => async (req, res, next) => {
        try { return await handler(req, res) } catch (error) { next(error) }
      },
    },
    'node:fs': {
      existsSync(filename) {
        calls.push(['exists', filename])
        return options.caExists !== false
      },
      readFileSync(filename) {
        calls.push(['read', filename])
        if (options.caError) throw options.caError
        return Buffer.from('custom CA')
      },
    },
    ldapts: { Client: class {
      constructor(settings) {
        calls.push(['client', settings])
        if (options.constructorError) throw options.constructorError
      }
      async bind(...args) {
        calls.push(['bind', ...args])
        if (options.bindError) throw options.bindError
      }
      async search(...args) {
        calls.push(['search', ...args])
        options.searchStarted?.resolve()
        if (options.searchDelay) await options.searchDelay.promise
        if (options.searchError) throw options.searchError
        return { searchEntries: options.entries || [] }
      }
      async unbind() {
        calls.push(['unbind'])
        options.unbindStarted?.resolve()
        if (options.unbindDelay) await options.unbindDelay.promise
        if (options.unbindError) throw options.unbindError
      }
    } },
  }
  let source = fs.readFileSync(overlay, 'utf8')
  const imports = [...source.matchAll(/^import (.+) from '([^']+)'$/gm)]
  assert.equal(imports.length, 7)
  for (const [statement, binding, dependency] of imports) {
    assert.ok(dependency in dependencies, `unexpected ESM import: ${dependency}`)
    source = source.replace(statement, `const ${binding} = dependencies[${JSON.stringify(dependency)}]`)
  }
  assert.match(source, /export default \{/)
  source = source.replace('export default {', 'module.exports = {')
  const moduleObject = { exports: {} }
  vm.runInNewContext(source, {
    module: moduleObject,
    dependencies,
    process: { env: {
      LDAP_CONTACTS: 'true',
      LDAP_SERVER: 'ldaps://directory.example.org',
      LDAP_BASE: 'dc=example,dc=org',
      LDAP_CONTACT_FILTER: '(mail=*)',
      ...options.env,
    } },
    console: { error: (...args) => errors.push(args) },
  }, { filename: overlay })
  const result = {}
  async function invoke() {
    await moduleObject.exports.getContacts({ session: { userId: 'current-user' } }, {
      json(data) {
        calls.push(['json'])
        result.data = plain(data)
      },
    }, error => { result.error = error })
    return result
  }
  return { calls, errors, locals, invoke, result }
}

test('overlay retains pinned native flow with only awaited LDAP enrichment', () => {
  const source = fs.readFileSync(overlay, 'utf8')
  const native = fs.readFileSync(original, 'utf8')
  const stripped = source
    .replace("import fs from 'node:fs'\nimport { Client } from 'ldapts'\n", '')
    .replace('  contacts = await getLdapContacts(contacts)\n\n', '')
    .replace(/async function getLdapContacts\(contacts\) \{[\s\S]*?\n\}\n\n(?=export default)/, '')
  assert.equal(stripped, native)
  for (const filename of [overlay, original]) {
    const syntax = spawnSync(process.execPath, ['--input-type=module', '--check'], {
      input: fs.readFileSync(filename, 'utf8'), encoding: 'utf8',
    })
    assert.equal(syntax.status, 0, syntax.stderr)
  }
})

for (const enabled of [undefined, 'false', '1', '']) {
  test(`LDAP disabled (${String(enabled)}) retains native ordering, filtering and hooks`, async () => {
    const extra = { id: 'module', email: 'module@example.org', type: 'external' }
    const current = fixture({ env: { LDAP_CONTACTS: enabled }, additionalContacts: [[extra]] })
    const { data } = await current.invoke()
    assert.deepEqual(data.contacts.map(contact => contact.id), ['first', 'second', 'module'])
    assert.deepEqual(data.contacts[0], {
      id: 'first', email: 'first@example.org', first_name: '', last_name: 'Local', type: 'user',
    })
    assert.equal(current.calls.some(call => call[0] === 'client'), false)
    assert.deepEqual(plain(current.calls[1]), ['ids', 'current-user', { limit: 50 }])
    assert.deepEqual(plain(current.calls[2]), ['users', ['first', 'second', 'holding'], {
      email: 1, first_name: 1, last_name: 1, holdingAccount: 1,
    }])
    assert.equal(current.calls[3][1], 'getContacts')
    assert.equal(current.calls[3][2], 'current-user')
    assert.equal(current.calls[3][3].length, 2)
  })
}

test('awaits delayed LDAP search and cleanup before formatting, hooks and response', async () => {
  const searchDelay = deferred()
  const searchStarted = deferred()
  const unbindDelay = deferred()
  const unbindStarted = deferred()
  const current = fixture({
    searchDelay, searchStarted, unbindDelay, unbindStarted,
    env: { LDAP_CONTACTS: 'TRUE', LDAP_BIND_USER: 'reader', LDAP_BIND_PW: 'password' },
    entries: [{ mail: 'ldap@example.org', givenName: 'Directory', sn: 'User' }],
  })
  const pending = current.invoke()
  await searchStarted.promise
  assert.equal(current.result.data, undefined)
  assert.equal(current.calls.some(call => call[0] === 'hooks'), false)
  searchDelay.resolve()
  await unbindStarted.promise
  assert.equal(current.result.data, undefined)
  assert.equal(current.calls.some(call => call[0] === 'hooks'), false)
  unbindDelay.resolve()
  const { data } = await pending
  assert.deepEqual(data.contacts[2], {
    email: 'ldap@example.org', first_name: 'Directory', last_name: 'User', type: 'user',
  })
  assert.deepEqual(plain(current.calls.slice(3, 6)), [
    ['client', { url: 'ldaps://directory.example.org' }],
    ['bind', 'reader', 'password'],
    ['search', 'dc=example,dc=org', { scope: 'sub', filter: '(mail=*)' }],
  ])
  assert.deepEqual(current.calls.slice(-3).map(call => call[0]), ['unbind', 'hooks', 'json'])
  assert.equal(current.calls.at(-2)[3][2].email, 'ldap@example.org')
  assert.equal(current.locals.length, 3)
})

test('LDAP mail arrays expand into distinct emails without replacing local identities', async () => {
  const current = fixture({ entries: [
    { mail: [' SECOND@EXAMPLE.ORG ', 'new@example.org', 'alias@example.org'], givenName: ['New'], sn: ['User'] },
    { mail: ['NEW@example.org', '', null, 12, ' alias@example.org ', 'another@example.org'] },
    { mail: ' first@EXAMPLE.org ' },
    { givenName: 'No mail' },
    { mail: [] },
    { mail: Buffer.from('not-a-string') },
  ] })
  const { data } = await current.invoke()
  assert.deepEqual(data.contacts.map(contact => contact.email), [
    'first@example.org', 'Second@example.org', 'new@example.org', 'alias@example.org', 'another@example.org',
  ])
  assert.equal(data.contacts[1].id, 'second')
  assert.equal(data.contacts[2].first_name, 'New')
  assert.equal(data.contacts[2].last_name, 'User')
  assert.equal(data.contacts[4].first_name, '')
  assert.equal(data.contacts.every(contact => !Array.isArray(contact)), true)
  assert.equal(current.calls.filter(call => call[0] === 'unbind').length, 1)
})

for (const caExists of [true, false]) {
  test(`custom CA uses authentication-manager configuration (exists=${caExists})`, async () => {
    const current = fixture({ caExists, env: { LDAP_SERVER_CACERT: '/certs/ldap.pem' } })
    await current.invoke()
    const settings = current.calls.find(call => call[0] === 'client')[1]
    if (caExists) {
      assert.equal(settings.tlsOptions.ca[0].toString(), 'custom CA')
      assert.equal(current.calls.find(call => call[0] === 'read')[1], '/certs/ldap.pem')
    } else {
      assert.equal(settings.tlsOptions, undefined)
      assert.equal(current.calls.some(call => call[0] === 'read'), false)
    }
  })
}

for (const failure of ['caError', 'constructorError', 'bindError', 'searchError', 'unbindError']) {
  test(`${failure} falls back to local contacts and cleans up every constructed client`, async () => {
    const current = fixture({
      [failure]: new Error(failure),
      env: { LDAP_BIND_USER: 'reader', LDAP_BIND_PW: 'password', LDAP_SERVER_CACERT: '/certs/ldap.pem' },
      entries: [{ mail: 'ldap@example.org' }],
    })
    const { data, error } = await current.invoke()
    assert.equal(error, undefined)
    assert.deepEqual(data.contacts.map(contact => contact.id), ['first', 'second'])
    assert.equal(current.errors.length, 1)
    assert.equal(current.calls.filter(call => call[0] === 'unbind').length,
      ['caError', 'constructorError'].includes(failure) ? 0 : 1)
    if (failure === 'bindError') assert.equal(current.calls.some(call => call[0] === 'search'), false)
  })
}

test('search and cleanup failures together still return local contacts', async () => {
  const current = fixture({ searchError: new Error('search'), unbindError: new Error('unbind') })
  assert.equal((await current.invoke()).data.contacts.length, 2)
  assert.equal(current.errors.length, 2)
})

for (const failure of ['localError', 'hookError']) {
  test(`native ${failure} still reaches express error handling`, async () => {
    const error = new Error(failure)
    const current = fixture({ [failure]: error })
    assert.equal((await current.invoke()).error, error)
    assert.equal(current.result.data, undefined)
    assert.equal(current.calls.filter(call => call[0] === 'unbind').length, failure === 'localError' ? 0 : 1)
  })
}

test('contact diff is exactly the generated baseline-to-overlay patch', () => {
  const generated = spawnSync('diff', [
    'ldap-overleaf-sl/sharelatex_ori/ContactController.js',
    'ldap-overleaf-sl/sharelatex/ContactController.js',
  ], { cwd: root, encoding: 'utf8' })
  assert.equal(generated.status, 1, generated.stderr)
  assert.equal(fs.readFileSync(diff, 'utf8'), generated.stdout)
})