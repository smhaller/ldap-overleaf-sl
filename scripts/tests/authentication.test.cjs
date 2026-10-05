const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { test } = require('node:test')

const root = path.resolve(__dirname, '../..')
const sourceDir = path.join(root, 'ldap-overleaf-sl/sharelatex')
const audit = { ipAddress: '127.0.0.1', info: { method: 'Password login' } }

function load(filename, mocks, globals = {}) {
  const module = { exports: {} }
  vm.runInNewContext(fs.readFileSync(path.join(sourceDir, filename), 'utf8'), {
    module,
    exports: module.exports,
    require(name) {
      assert.ok(Object.hasOwn(mocks, name), `Unstubbed dependency: ${name}`)
      return mocks[name]
    },
    URL,
    URLSearchParams,
    Buffer,
    ...globals,
  }, { filename })
  return module.exports
}

const callbackify = fn => function (...args) {
  const callback = args.pop()
  Promise.resolve().then(() => fn.apply(this, args)).then(
    result => callback(null, result), callback
  )
}
const promiseUtils = {
  callbackify,
  callbackifyMultiResult: (fn, keys) => function (...args) {
    const callback = args.pop()
    Promise.resolve().then(() => fn.apply(this, args)).then(
      result => callback(null, ...keys.map(key => result[key])), callback
    )
  },
  expressify: fn => fn,
  promisify: require('node:util').promisify,
}

function fixture(options = {}) {
  const env = {
    LDAP_SERVER: 'ldaps://directory.test',
    LDAP_BASE: 'dc=test',
    LDAP_USER_FILTER: '(mail=%m)',
    LDAP_BIND_USER: 'cn=reader,dc=test',
    LDAP_BIND_PW: 'reader-secret',
    ...options.env,
  }
  const users = new Map()
  const existing = options.user === false ? null : {
    _id: 'user-id', email: 'user@example.test', loginEpoch: 0,
    hashedPassword: 'local-hash', emails: [{ email: 'user@example.test' }],
    ...options.user,
  }
  if (existing) users.set(existing.email, existing)
  const calls = { binds: [], searches: [], unbinds: 0, updates: [], registrations: [],
    compares: [], hashes: [], hibp: [], audits: [], logs: [], clients: [] }
  const errors = Object.fromEntries([
    'InvalidEmailError', 'InvalidPasswordError', 'ParallelLoginError',
    'PasswordMustBeDifferentError', 'PasswordReusedError',
  ].map(name => [name, class extends Error {
    constructor(details) { super(name); this.info = details?.info }
  }]))
  const emailHelper = { parseEmail: email => typeof email === 'string' &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ? email.trim().toLowerCase() : null }
  const logger = Object.fromEntries(['warn', 'error', 'err', 'debug'].map(method =>
    [method, (...args) => calls.logs.push(args)]))
  const getter = {
    async getUser(query) {
      if (options.getterError) throw options.getterError
      return query._id ? [...users.values()].find(user => user._id === query._id) : users.get(query.email) || null
    },
    async getUserByMainEmail(email) { return users.get(email) || null },
  }
  class Client {
    constructor(config) { calls.clients.push(config) }
    async bind(dn, password) {
      calls.binds.push({ dn, password })
      if (options.bindFailure === calls.binds.length) throw new Error('bind denied')
    }
    async search(base, query) {
      calls.searches.push({ base, ...query })
      if (options.searchFailure === calls.searches.length) throw new Error('search denied')
      if (calls.searches.length > 1) return { searchEntries: options.admin ? [{}] : [] }
      return { searchEntries: options.entries || [{ dn: 'uid=user,dc=test',
        mail: 'user@example.test', uid: 'user', givenName: 'First', sn: 'Last' }] }
    }
    async unbind() {
      calls.unbinds++
      if (options.unbindFailure) throw new Error('cleanup denied')
    }
  }
  const escape = replacement => (strings, value) => String(value).replace(replacement, character =>
    `\\${character.charCodeAt(0).toString(16).padStart(2, '0')}`)
  const mocks = {
    '@overleaf/settings': { security: { bcryptRounds: 12 } },
    '../../models/User': { User: {
      findOne(...args) {
        assert.equal(args.length, 1, 'Mongoose findOne must not receive a callback')
        return { exec: () => getter.getUser(args[0]) }
      },
      updateOne(query, update, config) {
        assert.notEqual(typeof config, 'function')
        calls.updates.push({ query, update })
        return { async exec() {
          if (options.updateError) throw options.updateError
          const user = [...users.values()].find(user => user._id === query._id)
          if (update.$set?.['emails.$.confirmedAt']) {
            user.isAdmin = update.$set.isAdmin
            user.emails[0].confirmedAt = update.$set['emails.$.confirmedAt']
          }
          return { modifiedCount: options.modifiedCount ?? 1, matchedCount: options.matchedCount ?? 1 }
        } }
      },
    } },
    '../../infrastructure/mongodb': {
      ObjectId: class { constructor(value) { this.value = value } },
      db: { users: { async updateOne(query, update) {
        calls.updates.push({ query, update })
        return { modifiedCount: 1 }
      } } },
    },
    bcrypt: {
      getRounds: () => options.rounds ?? 12,
      async compare(password, hash) {
        calls.compares.push({ password, hash })
        if (options.compareError) throw options.compareError
        return options.localMatch ?? false
      },
      async genSalt() { return 'salt' },
      async hash(password) { calls.hashes.push(password); return 'new-hash' },
    },
    '../Helpers/EmailHelper': emailHelper,
    './AuthenticationErrors': errors,
    '@overleaf/promise-utils': promiseUtils,
    './HaveIBeenPwned': { promises: { async checkPasswordForReuse(password) {
      calls.hibp.push(password)
      if (options.hibpError) throw options.hibpError
      return options.reused ?? false
    } } },
    '../User/UserAuditLogHandler': { promises: { async addEntry(...args) {
      calls.audits.push(args)
      if (options.auditError) throw options.auditError
    } } },
    '@overleaf/logger': logger,
    '../Helpers/DiffHelper': { stringSimilarity: () => 0 },
    '@overleaf/metrics': { inc() {} },
    fs: { existsSync: () => true, readFileSync: () => Buffer.from('CA') },
    crypto: require('node:crypto'),
    ldapts: { Client },
    'ldap-escape': { filter: escape(/[()*\\\0]/g), dn: escape(/[,=+<>#;"\\\0]/g) },
    '../User/UserGetter': { promises: getter },
    '../User/UserRegistrationHandler': { promises: { async registerNewUser(details) {
      calls.registrations.push(details)
      if (options.registrationError) throw options.registrationError
      const user = { ...details, _id: 'new-id', loginEpoch: 0, hashedPassword: 'random-hash',
        emails: [{ email: details.email }] }
      delete user.password
      users.set(user.email, user)
      return user
    } } },
  }
  const manager = load('AuthenticationManager.js', mocks, { process: { env } })
  return { manager, calls, existing, env, errors, mocks, users }
}

test('local login preserves promise and callback result contracts, HIBP and hash upgrade', async () => {
  const { manager, calls, existing } = fixture({ env: { ALLOW_EMAIL_LOGIN: 'true' }, localMatch: true, rounds: 8 })
  const result = await manager.promises.authenticate({ email: existing.email }, 'local-secret', audit, {})
  assert.equal(result.user, existing)
  assert.equal(result.isPasswordReused, false)
  assert.equal(calls.binds.length, 0)
  assert.deepEqual(calls.hashes, ['local-secret'])
  assert.deepEqual(calls.hibp, ['local-secret'])
  await new Promise((resolve, reject) => manager.authenticate({ email: existing.email }, 'local-secret', audit, {},
    (error, user, reused) => { if (error) return reject(error); assert.equal(user, existing); assert.equal(reused, false); resolve() }))
})

test('local mismatch falls back to LDAP without rehashing or sending LDAP password to HIBP', async () => {
  const { manager, calls } = fixture({ env: { ALLOW_EMAIL_LOGIN: '1' }, rounds: 4 })
  const result = await manager.promises.authenticate({ email: 'user@example.test' }, 'ldap-secret', audit, {})
  assert.ok(result.user)
  assert.equal(calls.compares.length, 1)
  assert.equal(calls.binds.length, 2)
  assert.equal(calls.unbinds, 1)
  assert.equal(calls.hashes.length, 0)
  assert.equal(calls.hibp.length, 0)
  assert.equal(calls.updates.length, 1)
  assert.equal(calls.updates[0].update.$inc.loginEpoch, 1)
})

for (const flag of [undefined, '', 'false', '0']) {
  test(`local fallback disabled by ${String(flag)}`, async () => {
    const { manager, calls } = fixture({ env: { ALLOW_EMAIL_LOGIN: flag }, localMatch: true, bindFailure: 2 })
    const result = await manager.promises.authenticate({ email: 'user@example.test' }, 'bad-secret', audit, {})
    assert.equal(result.user, null)
    assert.equal(calls.compares.length, 0)
    assert.equal(calls.audits[0][1], 'failed-password-match')
    assert.ok(calls.updates[0].update.$set.lastFailedLogin)
    assert.equal(calls.unbinds, 1)
  })
}

for (const flag of ['false', '0', '', 'invalid']) {
  test(`LDAP fallback disabled by ${flag} even with OAuth enabled`, async () => {
    const { manager, calls } = fixture({ env: {
      OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'false', ALLOW_LDAP_LOGIN: flag,
    } })
    const result = await manager.promises.authenticate({ email: 'user@example.test' }, 'ldap-secret', audit, {})
    assert.equal(result.user, null)
    assert.equal(calls.clients.length, 0)
    assert.equal(calls.compares.length, 0)
  })
}

test('OAuth permits database-only fallback without contacting LDAP', async () => {
  const { manager, calls, existing } = fixture({ env: {
    OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'true', ALLOW_LDAP_LOGIN: 'false',
  }, localMatch: true })
  assert.equal((await manager.promises.authenticate({ email: existing.email }, 'local-secret', audit, {})).user, existing)
  assert.equal(calls.clients.length, 0)
  assert.equal(calls.compares.length, 1)
})

for (const denial of [{ bindFailure: 1 }, { bindFailure: 2 }, { searchFailure: 1 },
  { entries: [] }, { entries: [{}, {}] }, { entries: [{ dn: 'uid=user', mail: '' }] }]) {
  test(`LDAP denial and cleanup: ${JSON.stringify(denial)}`, async () => {
    const { manager, calls } = fixture({ user: false, ...denial })
    assert.equal((await manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {})).user, null)
    assert.equal(calls.unbinds, 1)
    assert.equal(calls.registrations.length, 0)
    assert.equal(calls.updates.length, 0)
  })
}

test('empty passwords cannot perform unauthenticated LDAP binds', async () => {
  const { manager, calls } = fixture()
  assert.equal((await manager.promises.authenticate({ email: 'user@example.test' }, '', audit, {})).user, null)
  assert.equal(calls.clients.length, 0)
})

test('direct bind uses DN escaping, filter escaping, CA and one bind only', async () => {
  const { manager, calls } = fixture({ user: false, env: {
    LDAP_BINDDN: 'uid=%u,dc=test', LDAP_USER_FILTER: '(|(uid=%u)(mail=%m))', LDAP_SERVER_CACERT: '/ca.pem',
  } })
  await manager.promises.authenticate({ email: 'a,*)(x@example.test' }, 'ldap-secret', audit, {})
  assert.equal(calls.binds.length, 1)
  assert.equal(calls.binds[0].dn, 'uid=a\\2c*)(x,dc=test')
  assert.equal(calls.searches[0].filter, '(|(uid=a,\\2a\\29\\28x)(mail=a,\\2a\\29\\28x@example.test))')
  assert.equal(calls.clients[0].tlsOptions.ca[0].toString(), 'CA')
  assert.equal(calls.unbinds, 1)
})

test('LDAP provisioning uses canonical mail, random password, confirmed email and admin group', async () => {
  const { manager, calls } = fixture({ user: false, admin: true, env: { LDAP_ADMIN_GROUP_FILTER: '(uid=%u)' } })
  const query = { email: 'alias@example.test' }
  const result = await manager.promises.authenticate(query, 'ldap-secret', audit, {})
  assert.equal(query.email, 'alias@example.test')
  assert.equal(result.user.email, 'user@example.test')
  assert.equal(result.user.isAdmin, true)
  assert.ok(result.user.emails[0].confirmedAt)
  assert.match(calls.registrations[0].password, /^[0-9a-f]{64}$/)
  assert.notEqual(calls.registrations[0].password, 'ldap-secret')
  assert.equal(JSON.stringify(calls.logs).includes(calls.registrations[0].password), false)
  assert.equal(JSON.stringify(calls.updates).includes('ldap-secret'), false)
})

test('admin search failure denies admin but does not skip reader-mode password bind', async () => {
  const { manager, calls } = fixture({ user: false, searchFailure: 2, env: { LDAP_ADMIN_GROUP_FILTER: '(uid=%u)' } })
  const result = await manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {})
  assert.equal(result.user.isAdmin, false)
  assert.equal(calls.binds.length, 2)
})

test('upstream parallel-login and failed audit behavior remain intact', async () => {
  const failed = fixture({ bindFailure: 2, modifiedCount: 0 })
  await assert.rejects(failed.manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {}), failed.errors.ParallelLoginError)
  const auditFailed = fixture({ bindFailure: 2, auditError: new Error('audit unavailable') })
  assert.equal((await auditFailed.manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {})).user, null)
})

test('local HIBP enforcement and known-device warning contracts are preserved', async () => {
  const { manager, errors } = fixture({ env: { ALLOW_EMAIL_LOGIN: 'yes' }, localMatch: true, reused: true })
  await assert.rejects(manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {}), errors.PasswordReusedError)
  assert.equal((await manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, { enforceHIBPCheck: false })).isPasswordReused, true)
})

test('password reset checks local hash regardless of LDAP login flag', async () => {
  const { manager, calls, errors, existing } = fixture({ localMatch: true })
  await assert.rejects(manager.promises.setUserPasswordInV2(existing, 'different-secret'), errors.PasswordMustBeDifferentError)
  assert.equal(calls.binds.length, 0)
  assert.equal(calls.compares.length, 1)
  assert.equal(calls.hashes.length, 0)
})

test('registration and database failures propagate without successful authentication', async () => {
  for (const options of [{ user: false, registrationError: new Error('register failed') },
    { updateError: new Error('database failed') }, { getterError: new Error('lookup failed') }]) {
    const { manager } = fixture(options)
    await assert.rejects(manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {}), /failed/)
  }
})

test('LDAP cleanup errors do not mask a denial or replace authenticated credentials', async () => {
  for (const bindFailure of [undefined, 2]) {
    const { manager, calls } = fixture({ unbindFailure: true, bindFailure })
    const result = await manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {})
    assert.equal(Boolean(result.user), !bindFailure)
    assert.equal(calls.unbinds, 1)
    assert.equal(calls.hashes.length, 0)
  }
})

test('provisioning reuses existing users without changing admin or confirmation', async () => {
  const { manager, calls, existing } = fixture({ user: { isAdmin: false } })
  assert.equal(await manager.promises.provisionExternalUser({ email: 'USER@example.test', isAdmin: true }), existing)
  assert.equal(existing.isAdmin, false)
  assert.equal(calls.registrations.length, 0)
  assert.equal(calls.updates.length, 0)
})

test('provisioning fails if email confirmation did not match the new user', async () => {
  const { manager } = fixture({ user: false, matchedCount: 0 })
  await assert.rejects(manager.promises.provisionExternalUser({ email: 'user@example.test' }), /Could not confirm/)
})

test('bcrypt errors propagate instead of silently falling back to LDAP', async () => {
  const { manager, calls } = fixture({ env: { ALLOW_EMAIL_LOGIN: 'true' }, compareError: new Error('bcrypt failure') })
  await assert.rejects(manager.promises.authenticate({ email: 'user@example.test' }, 'secret', audit, {}), /bcrypt failure/)
  assert.equal(calls.clients.length, 0)
})

function oauthFixture(options = {}) {
  const auth = fixture(options)
  Object.assign(auth.env, {
    OVERLEAF_SITE_URL: 'https://overleaf.example.test',
    OAUTH2_AUTHORIZATION_URL: 'https://identity.test/authorize?audience=overleaf',
    OAUTH2_TOKEN_URL: 'https://identity.test/token',
    OAUTH2_PROFILE_URL: 'https://identity.test/profile',
    OAUTH2_CLIENT_ID: 'client&value',
    OAUTH2_CLIENT_SECRET: 'oauth-client-secret',
    OAUTH2_SCOPE: 'openid email profile',
    ...options.env,
  })
  const calls = { fetches: [], redirects: [], errors: [], logins: [], hooks: [], events: [] }
  const noop = () => {}
  const mocks = {
    './AuthenticationManager': auth.manager,
    './SessionManager': {},
    '@overleaf/o-error': { tag: noop },
    '../Security/LoginRateLimiter': { recordSuccessfulLogin(email, callback) { callback() } },
    '../User/UserUpdater': { updateUser(id, update, callback) { callback() } },
    '@overleaf/metrics': auth.mocks['@overleaf/metrics'],
    '@overleaf/logger': auth.mocks['@overleaf/logger'],
    querystring: require('node:querystring'),
    '@overleaf/settings': auth.mocks['@overleaf/settings'],
    'basic-auth': noop,
    tsscmp: (expected, actual) => expected === actual,
    '../User/UserHandler': { populateTeamInvites(user, callback) { callback() } },
    '../User/UserSessionsManager': { trackSession: noop },
    '../Analytics/AnalyticsManager': { recordEventForUserInBackground: (...args) => calls.events.push(args), identifyUser: noop },
    passport: {},
    '../Notifications/NotificationsBuilder': { ipMatcherAffiliation: () => ({ create: noop }) },
    '../Helpers/UrlHelper': { getSafeRedirectPath: value => value },
    '../Helpers/AsyncFormHelper': { redirect: (req, res, value) => res.redirect(value) },
    lodash: { get: (object, keys) => keys.reduce((value, key) => value?.[key], object) },
    '../User/UserAuditLogHandler': auth.mocks['../User/UserAuditLogHandler'],
    '../Analytics/AnalyticsRegistrationSourceHelper': { clearSource: noop, clearInbound: noop },
    '../../infrastructure/RequestContentTypeDetection': { acceptsJson: () => false },
    '../Helpers/AdminAuthorizationHelper': { hasAdminAccess: user => user.isAdmin },
    '../../infrastructure/Modules': { promises: { hooks: { async fire(...args) {
      calls.hooks.push(args)
      return []
    } } } },
    '@overleaf/promise-utils': promiseUtils,
    './AuthenticationErrors': { handleAuthenticateErrors: error => ({ error }) },
    '../Helpers/EmailHelper': auth.mocks['../Helpers/EmailHelper'],
    crypto: require('node:crypto'),
  }
  const controller = load('AuthenticationController.js', mocks, {
    process: { env: auth.env },
    async fetch(url, config) {
      calls.fetches.push({ url, ...config })
      const token = calls.fetches.length === 1
      if (options.fetchError) throw new Error('network failed')
      return {
        ok: token ? options.tokenOk ?? true : options.profileOk ?? true,
        async json() {
          if (options.jsonError) throw new Error('invalid JSON')
          return token ? options.token ?? { access_token: 'oauth-access-token' } : options.profile ?? { email: 'user@example.test' }
        },
      }
    },
  })
  const req = {
    query: { code: 'oauth-code', state: 'expected-state', ...options.query },
    session: { oauth2State: 'expected-state', csrfSecret: 'old-csrf', __tmp: true,
      save(callback) { callback() }, ...options.session },
    ip: '127.0.0.1', sessionID: 'session-id',
    login(user, config, callback) { calls.logins.push(user); callback() },
  }
  const res = { redirect: value => calls.redirects.push(value) }
  const next = error => calls.errors.push(error)
  return { ...auth, controller, oauthCalls: calls, req, res, next }
}

test('OAuth authorization uses strong state and correctly encoded parameters', () => {
  const { controller, req, res, next, oauthCalls } = oauthFixture()
  controller.oauth2Redirect(req, res, next)
  const url = new URL(oauthCalls.redirects[0])
  assert.match(req.session.oauth2State, /^[0-9a-f]{64}$/)
  assert.equal(url.searchParams.get('state'), req.session.oauth2State)
  assert.equal(url.searchParams.get('client_id'), 'client&value')
  assert.equal(url.searchParams.get('scope'), 'openid email profile')
  assert.equal(url.searchParams.get('redirect_uri'), 'https://overleaf.example.test/oauth/callback')
  assert.equal(url.searchParams.get('audience'), 'overleaf')
  assert.equal(oauthCalls.errors.length, 0)
})

for (const stateCase of [
  { query: { state: 'wrong' } },
  { query: { state: undefined }, session: { oauth2State: undefined } },
  { query: { state: ['expected-state'] } },
  { query: { code: undefined } },
  { query: { code: ['oauth-code'] } },
]) {
  test(`OAuth rejects invalid state or code: ${JSON.stringify(stateCase)}`, async () => {
    const { controller, req, res, next, oauthCalls, calls } = oauthFixture(stateCase)
    await controller.oauth2Callback(req, res, next)
    assert.equal(req.session.oauth2State, undefined)
    assert.equal(oauthCalls.fetches.length, 0)
    assert.equal(calls.registrations.length, 0)
    assert.deepEqual(oauthCalls.redirects, ['/login'])
  })
}

for (const contentType of ['application/json', 'application/x-www-form-urlencoded']) {
  test(`OAuth provisions then completes audited upstream login using ${contentType}`, async () => {
    const { controller, req, res, next, oauthCalls, calls } = oauthFixture({ user: false, env: {
      OAUTH2_TOKEN_CONTENT_TYPE: contentType, OAUTH2_USER_ATTR_EMAIL: 'mail',
      OAUTH2_USER_ATTR_FIRSTNAME: 'given', OAUTH2_USER_ATTR_LASTNAME: 'surname', OAUTH2_USER_ATTR_IS_ADMIN: 'admin',
    }, profile: { mail: 'USER@example.test', given: 'First', surname: 'Last', admin: 'false' } })
    await controller.oauth2Callback(req, res, next)
    assert.equal(oauthCalls.errors.length, 0)
    assert.equal(oauthCalls.logins.length, 1)
    assert.equal(oauthCalls.logins[0].email, 'user@example.test')
    assert.equal(oauthCalls.logins[0].isAdmin, false)
    assert.ok(oauthCalls.logins[0].emails[0].confirmedAt)
    assert.equal(calls.registrations[0].first_name, 'First')
    assert.equal(calls.registrations[0].last_name, 'Last')
    assert.equal(calls.audits[0][1], 'login')
    assert.equal(calls.audits[0][4].method, 'OAuth2 login')
    assert.equal(oauthCalls.hooks[0][0], 'preFinishLogin')
    assert.deepEqual(oauthCalls.redirects, ['/project'])
    assert.equal(req.session.csrfSecret, undefined)
    assert.equal(req.session.__tmp, undefined)
    const body = contentType === 'application/json' ? JSON.parse(oauthCalls.fetches[0].body) : Object.fromEntries(new URLSearchParams(oauthCalls.fetches[0].body))
    assert.equal(body.client_secret, 'oauth-client-secret')
    assert.equal(body.code, 'oauth-code')
    assert.equal(oauthCalls.fetches[1].headers.Authorization, 'Bearer oauth-access-token')
    const logs = JSON.stringify(calls.logs)
    for (const secret of ['oauth-client-secret', 'oauth-access-token', 'oauth-code', calls.registrations[0].password]) {
      assert.equal(logs.includes(secret), false)
    }
  })
}

test('OAuth existing users are not reprovisioned and state cannot be replayed', async () => {
  const { controller, req, res, next, oauthCalls, calls } = oauthFixture()
  await controller.oauth2Callback(req, res, next)
  assert.equal(calls.registrations.length, 0)
  await controller.oauth2Callback(req, res, next)
  assert.equal(oauthCalls.fetches.length, 2)
  assert.equal(oauthCalls.logins.length, 1)
  assert.deepEqual(oauthCalls.redirects, ['/project', '/login'])
})

test('OAuth admin claim must be explicitly configured', async () => {
  const { controller, req, res, next, oauthCalls } = oauthFixture({ user: false,
    profile: { email: 'user@example.test', undefined: true, isAdmin: true } })
  await controller.oauth2Callback(req, res, next)
  assert.equal(oauthCalls.errors.length, 0)
  assert.equal(oauthCalls.logins[0].isAdmin, false)
})

for (const failure of [{ tokenOk: false }, { token: {} }, { profileOk: false },
  { profile: { email: ['user@example.test'] } }, { profile: { email: 'invalid' } },
  { profile: { email: 'user@example.test', email_verified: false } },
  { fetchError: true }, { jsonError: true },
  { registrationError: new Error('registration failed') }]) {
  test(`OAuth failures do not finish login: ${JSON.stringify(failure)}`, async () => {
    const { controller, req, res, next, oauthCalls } = oauthFixture({ user: false, ...failure })
    await controller.oauth2Callback(req, res, next)
    assert.equal(oauthCalls.errors.length, 1)
    assert.equal(oauthCalls.logins.length, 0)
    assert.equal(req.session.oauth2State, undefined)
  })
}

test('OAuth preserves upstream suspended-account denial and audit failures', async () => {
  const suspended = oauthFixture({ user: { suspended: true } })
  await suspended.controller.oauth2Callback(suspended.req, suspended.res, suspended.next)
  assert.deepEqual(suspended.oauthCalls.redirects, ['/account-suspended'])
  assert.equal(suspended.oauthCalls.logins.length, 0)
  const auditFailed = oauthFixture({ auditError: new Error('audit failed') })
  await auditFailed.controller.oauth2Callback(auditFailed.req, auditFailed.res, auditFailed.next)
  assert.equal(auditFailed.oauthCalls.errors.length, 1)
  assert.equal(auditFailed.oauthCalls.logins.length, 0)
})

test('upstream exports remain available', () => {
  const { manager, controller } = oauthFixture()
  for (const name of ['_validatePasswordNotTooSimilar', 'validateEmail', 'validatePassword',
    'getMessageForInvalidPasswordError', 'authenticate', 'setUserPassword', 'checkRounds',
    'hashPassword', 'setUserPasswordInV2', 'promises']) {
    assert.ok(manager[name], name)
  }
  assert.equal(controller.promises.finishLogin, controller._finishLoginAsync)
})