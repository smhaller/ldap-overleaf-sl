const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { spawnSync } = require('node:child_process')
const { test } = require('node:test')

const root = path.resolve(__dirname, '../..')
const overlay = path.join(root, 'ldap-overleaf-sl/sharelatex')
const original = path.join(root, 'ldap-overleaf-sl/sharelatex_ori')
const read = name => fs.readFileSync(path.join(overlay, name), 'utf8')
const plain = value => JSON.parse(JSON.stringify(value))

function load(name, dependencies) {
  const moduleObject = { exports: {} }
  vm.runInNewContext(read(name), {
    module: moduleObject,
    require(dependency) {
      assert.ok(dependency in dependencies, `unexpected dependency: ${dependency}`)
      return dependencies[dependency]
    },
  }, { filename: name })
  return moduleObject.exports
}

function editor(historyBlobs = true) {
  return load('ProjectEditorHandler.js', {
    lodash: {
      defaults(target, defaults) {
        for (const [key, value] of Object.entries(defaults)) {
          if (target[key] === undefined) target[key] = value
        }
        return target
      },
      filter: (values, predicate) => values.filter(predicate),
      pick: (value, keys) => Object.fromEntries(
        keys.filter(key => key in value).map(key => [key, value[key]])
      ),
    },
    path,
    '../../infrastructure/Features': { hasFeature: () => historyBlobs },
  })
}

function review() {
  const calls = []
  const events = []
  const failures = {}
  const ownerId = '111111111111111111111111'
  const formerId = '222222222222222222222222'
  const ranges = [{ _id: 'doc', ranges: { changes: [{ metadata: { user_id: formerId } }] } }]
  const operation = (name, result) => async (...args) => {
    calls.push([name, ...args])
    if (failures[name]) throw failures[name]
    return typeof result === 'function' ? result(...args) : result
  }
  const controller = load('TrackChangesController.js', {
    '../Chat/ChatApiHandler': { promises: Object.fromEntries([
      'sendComment', 'editMessage', 'deleteMessage', 'resolveThread',
      'reopenThread', 'deleteThread', 'getThreads',
    ].map(name => [name, operation(`chat.${name}`, name === 'sendComment' ? { id: 'message' } : {})])) },
    '../Chat/ChatManager': { promises: { injectUserInfoIntoThreads: operation('inject') } },
    '../Editor/EditorRealTimeController': { emitToRoom: (...args) => events.push(args) },
    '../Authentication/SessionManager': { getLoggedInUserId: session => session?.userId },
    '../User/UserInfoManager': { promises: { getPersonalInfo: operation('user', userId => ({ _id: userId, email: 'private', first_name: 'First' })) } },
    '../User/UserInfoController': { formatPersonalInfo: user => ({ id: String(user._id), first_name: user.first_name, email: user.email }) },
    '../Docstore/DocstoreManager': { promises: { getAllRanges: operation('ranges', ranges) } },
    '../DocumentUpdater/DocumentUpdaterHandler': { promises: Object.fromEntries([
      'flushProjectToMongo', 'acceptChanges', 'resolveThread', 'reopenThread', 'deleteThread',
    ].map(name => [name, operation(`doc.${name}`)])) },
    '../Collaborators/CollaboratorsGetter': { promises: { getMemberIds: operation('members', [ownerId]) } },
    '../../models/Project': { Project: { updateOne: (...args) => ({ exec: () => operation('update')(...args) }) } },
  })
  async function invoke(name, body = {}, params = {}, userId = ownerId) {
    const result = {}
    await controller[name]({
      body,
      params: { project_id: 'project', doc_id: 'doc', thread_id: 'thread', message_id: 'message', ...params },
      session: { userId },
    }, {
      sendStatus: status => { result.status = status },
      json: data => { result.data = plain(data) },
    }, error => { result.error = error })
    return result
  }
  return { calls, events, failures, invoke, ownerId, formerId, ranges }
}

test('editor matches pinned upstream except the two intentional feature defaults', () => {
  const expected = fs.readFileSync(path.join(original, 'ProjectEditorHandler.js'), 'utf8')
    .replace('trackChangesAvailable: false', 'trackChangesAvailable: true')
    .replace('trackChanges: false', 'trackChanges: true')
  assert.equal(read('ProjectEditorHandler.js'), expected)
})

test('modern editor preserves bibliography, pending roles, file hashes and feature flags', () => {
  const handler = editor()
  const result = handler.buildProjectModelView({
    mainBibliographyDoc_id: 'bibliography',
    rootFolder: [{ fileRefs: [null, { hash: 'blob' }] }],
    track_changes: { __guests__: true },
  }, [{ user: { _id: 'owner', features: {} }, privilegeLevel: 'owner', pendingEditor: true }], [])
  assert.equal(result.mainBibliographyDoc_id, 'bibliography')
  assert.equal(result.owner.pendingEditor, true)
  assert.equal(result.rootFolder[0].fileRefs[0].hash, 'blob')
  assert.equal(result.features.trackChanges, true)
  assert.equal(result.features.trackChangesVisible, true)
  assert.deepEqual(plain(result.trackChangesState), { __guests__: true })
  assert.equal('hash' in editor(false).buildFileModelView({ hash: 'blob' }), false)
  const disabled = handler.buildProjectModelView({ rootFolder: [{}] }, [
    { user: { features: { trackChanges: false, trackChangesVisible: false } }, privilegeLevel: 'owner' },
  ], [])
  assert.equal(disabled.features.trackChanges, false)
  assert.equal(disabled.features.trackChangesVisible, false)
})

for (const enabled of [true, false]) {
  test(`toggle persists ${enabled} without coercion`, async () => {
    const fixture = review()
    assert.equal((await fixture.invoke('trackChanges', { on: enabled })).status, 204)
    assert.equal(fixture.calls[0][2].$set.track_changes, enabled)
    assert.deepEqual(plain(fixture.events[0]), ['project', 'toggle-track-changes', enabled])
  })
}

test('per-user and guest state does not mutate the request body', async () => {
  const fixture = review()
  const body = { on_for: { [fixture.ownerId]: false }, on_for_guests: true }
  assert.equal((await fixture.invoke('trackChanges', body)).status, 204)
  assert.deepEqual(plain(fixture.calls[0][2].$set.track_changes), { [fixture.ownerId]: false, __guests__: true })
  assert.equal('__guests__' in body.on_for, false)
  assert.equal((await fixture.invoke('trackChanges', { on_for_guests: false })).status, 204)
})

for (const body of [{}, { on: 'false' }, { on_for: null }, { on_for: [] }, { on_for: { invalid: true } }, { on_for_guests: 'true' }]) {
  test(`rejects malformed toggle ${JSON.stringify(body)}`, async () => {
    const fixture = review()
    assert.equal((await fixture.invoke('trackChanges', body)).error.status, 400)
    assert.equal(fixture.calls.length, 0)
    assert.equal(fixture.events.length, 0)
  })
}

test('database failures are forwarded with no event or success response', async () => {
  const fixture = review()
  fixture.failures.update = new Error('database failure')
  const result = await fixture.invoke('trackChanges', { on: true })
  assert.equal(result.error, fixture.failures.update)
  assert.equal(result.status, undefined)
  assert.equal(fixture.events.length, 0)
})

test('accept changes uses the pinned promise signature and emits after success', async () => {
  const fixture = review()
  assert.equal((await fixture.invoke('acceptChanges', { change_ids: ['change'] })).status, 204)
  assert.deepEqual(plain(fixture.calls), [['doc.acceptChanges', 'project', 'doc', ['change']]])
  assert.deepEqual(plain(fixture.events), [['project', 'accept-changes', 'doc', ['change']]])
  assert.equal((await fixture.invoke('acceptChanges', { change_ids: 'change' })).error.status, 400)
})

test('ranges flush before retrieval and expose id without mutating source', async () => {
  const fixture = review()
  const result = await fixture.invoke('getAllRanges')
  assert.deepEqual(fixture.calls.map(call => call[0]), ['doc.flushProjectToMongo', 'ranges'])
  assert.equal(result.data[0].id, 'doc')
  assert.equal('_id' in result.data[0], false)
  assert.equal(fixture.ranges[0]._id, 'doc')
})

test('change users include former authors and anonymous users with native formatting', async () => {
  const fixture = review()
  const result = await fixture.invoke('getChangesUsers')
  assert.deepEqual(result.data.map(user => user.id), [fixture.ownerId, fixture.formerId, null])
  assert.equal(result.data.some(user => '_id' in user), false)
  assert.equal(result.data[0].email, 'private')
})

for (const name of ['resolveThread', 'reopenThread', 'deleteThread']) {
  test(`${name} sequences verified document and chat signatures`, async () => {
    const fixture = review()
    assert.equal((await fixture.invoke(name)).status, 204)
    assert.deepEqual(plain(fixture.calls[0]), [`doc.${name}`, 'project', 'doc', 'thread', fixture.ownerId])
    assert.deepEqual(plain(fixture.calls[1]), name === 'resolveThread'
      ? [`chat.${name}`, 'project', 'thread', fixture.ownerId]
      : [`chat.${name}`, 'project', 'thread'])
    assert.equal(fixture.events.length, 1)
  })
  test(`${name} document failure prevents chat mutation and broadcast`, async () => {
    const fixture = review()
    fixture.failures[`doc.${name}`] = new Error('document failure')
    assert.equal((await fixture.invoke(name)).error, fixture.failures[`doc.${name}`])
    assert.equal(fixture.calls.length, 1)
    assert.equal(fixture.events.length, 0)
  })
}

test('legacy chat-only resolve never passes undefined doc IDs to document updater', async () => {
  const fixture = review()
  assert.equal((await fixture.invoke('resolveThread', {}, { doc_id: undefined })).status, 204)
  assert.equal(fixture.calls[0][0], 'chat.resolveThread')
})

test('comment events use the native personal-info formatter', async () => {
  const fixture = review()
  assert.equal((await fixture.invoke('sendComment', { content: 'comment' })).status, 204)
  assert.deepEqual(plain(fixture.calls[0]), ['chat.sendComment', 'project', 'thread', fixture.ownerId, 'comment'])
  assert.deepEqual(plain(fixture.events[0][3].user), { id: fixture.ownerId, first_name: 'First', email: 'private' })
})

test('message mutations require logged-in users and use current API arguments', async () => {
  const fixture = review()
  assert.equal((await fixture.invoke('editMessage', { content: 'edited' })).status, 204)
  assert.deepEqual(plain(fixture.calls[0]), ['chat.editMessage', 'project', 'thread', 'message', fixture.ownerId, 'edited'])
  assert.equal((await fixture.invoke('deleteMessage')).status, 204)
  assert.deepEqual(plain(fixture.calls[1]), ['chat.deleteMessage', 'project', 'thread', 'message'])
  for (const name of ['sendComment', 'editMessage', 'deleteMessage', 'resolveThread', 'reopenThread', 'deleteThread']) {
    assert.equal((await fixture.invoke(name, {}, {}, null)).error.status, 401)
  }
})

test('router executes READ gates for retrieval and WRITE gates for every review mutation', () => {
  const source = read('router.js')
  const start = source.indexOf('  const reviewRoutes = [')
  const end = source.indexOf("  webRouter.get('*', ErrorController.notFound)", start)
  assert.ok(start >= 0 && end > start)
  const routes = []
  const restricted = () => {}
  const readGate = () => {}
  const writeGate = () => {}
  vm.runInNewContext(source.slice(start, end), {
    webRouter: Object.fromEntries(['get', 'post', 'delete'].map(method => [method, (...args) => routes.push([method, ...args])])),
    AuthorizationMiddleware: { blockRestrictedUserFromProject: restricted, ensureUserCanReadProject: readGate, ensureUserCanWriteProjectContent: writeGate },
    TrackChangesController: new Proxy({}, { get: (_, name) => name }),
  })
  assert.equal(routes.length, 12)
  for (const [method, routePath, restrictedGate, gate] of routes) {
    assert.equal(restrictedGate, restricted, routePath)
    assert.equal(gate, method === 'get' ? readGate : writeGate, routePath)
  }
  const syntax = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: source, encoding: 'utf8' })
  assert.equal(syntax.status, 0, syntax.stderr)
})

test('OAuth-only redirect remains conditional on LDAP and email login settings', () => {
  const source = read('router.js')
  const start = source.indexOf('  const allowPasswordLogin =')
  const end = source.indexOf("  AuthenticationController.addEndpointToLoginWhitelist('/login')", start)
  assert.ok(start >= 0 && end > start)
  for (const [env, expected] of [
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'false' }, 'redirect'],
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'false', LDAP_SERVER: 'ldap://server' }, 'login'],
    [{ OAUTH2_ENABLED: 'false', ALLOW_EMAIL_LOGIN: 'false' }, 'login'],
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'true' }, 'login'],
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'false', LDAP_SERVER: 'ldap://server', ALLOW_LDAP_LOGIN: 'false' }, 'redirect'],
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'true', LDAP_SERVER: 'ldap://server', ALLOW_LDAP_LOGIN: 'false' }, 'login'],
    [{ OAUTH2_ENABLED: 'true', ALLOW_EMAIL_LOGIN: 'false', LDAP_SERVER: 'ldap://server', ALLOW_LDAP_LOGIN: 'yes' }, 'login'],
    [{ OAUTH2_ENABLED: 'true' }, 'redirect'],
  ]) {
    let handler
    vm.runInNewContext(source.slice(start, end), {
      process: { env }, webRouter: { get: (_, value) => { handler = value } },
      UserPagesController: { loginPage: 'login' },
    })
    if (expected === 'login') assert.equal(handler, 'login')
    else handler({}, { redirect: destination => assert.equal(destination, '/oauth/redirect') })
  }
  for (const endpoint of ['/oauth/redirect', '/oauth/callback']) {
    assert.ok(source.includes(`addEndpointToLoginWhitelist('${endpoint}')`))
  }
})

test('admin templates retain native tabs, CSRF forms and registration without Angular', () => {
  for (const name of ['admin-index.pug', 'admin-sysadmin.pug']) {
    const source = read(name)
    assert.match(source, /extends \.\.\/layout-marketing/)
    assert.match(source, /data-ol-bookmarkable-tabset/)
    assert.match(source, /href='\/admin\/register'/)
    assert.doesNotMatch(source, /ng-controller|ng-click|ng-model|RegisterUsersController|\t+tabset\(/)
    for (const action of ['messages', 'messages/clear', 'openEditor', 'closeEditor', 'disconnectAllUsers']) {
      assert.ok(source.includes(`/admin/${action}`))
    }
    assert.match(source, /name="_csrf"/)
  }
})

test('pinned Bootstrap 5 navbar and LDAP/OAuth markup are present', () => {
  const navbar = read('navbar-marketing-bootstrap-5.pug')
  assert.equal(navbar, fs.readFileSync(path.join(original, 'navbar-marketing-bootstrap-5.pug'), 'utf8'))
  assert.match(navbar, /data-bs-toggle="dropdown"/)
  assert.match(navbar, /href="\/admin\/user"/)
  const login = read('login.pug')
  assert.match(login, /type='text'/)
  assert.match(login, /OAUTH2_ENABLED === 'true'/)
  assert.match(login, /OAUTH2_PROVIDER \|\| 'OAuth'/)
})

test('all owned diffs and the Dockerfile compatibility controller match working files', () => {
  for (const name of [
    'router.js', 'ProjectEditorHandler.js', 'TrackChangesController.js',
    'login.pug', 'navbar-marketing.pug', 'navbar-marketing-bootstrap-5.pug',
    'admin-index.pug', 'admin-sysadmin.pug',
  ]) {
    const originalPath = `ldap-overleaf-sl/sharelatex_ori/${name}`
    const overlayPath = `ldap-overleaf-sl/sharelatex/${name}`
    const expected = spawnSync('diff', [
      '-u', '--label', originalPath, '--label', overlayPath, originalPath, overlayPath,
    ], { cwd: root, encoding: 'utf8' })
    assert.ok(expected.status === 0 || expected.status === 1, expected.stderr)
    const actual = fs.readFileSync(path.join(root, 'ldap-overleaf-sl/sharelatex_diff', `${name}.diff`), 'utf8')
    assert.equal(actual, expected.stdout, name)
  }
  assert.equal(read('TrackChangesController.js'), fs.readFileSync(
    path.join(root, 'ldap-overleaf-sl/sharelatex_diff/TrackChangesController.js'), 'utf8'
  ))
  assert.equal(fs.readFileSync(path.join(original, 'TrackChangesController.js'), 'utf8'), '')
})

test('Pug renders native admin and login templates', { skip: !process.env.PUG_MODULE_PATH }, () => {
  const pug = require(process.env.PUG_MODULE_PATH)
  const mixins = ['formMessagesNewStyle', 'customFormMessageNewStyle', 'bookmarkable-tabset-header']
    .map(name => `mixin ${name}()\n\tblock\n`).join('')
  const locals = {
    translate: value => value, csrfToken: 'csrf', hasFeature: () => false,
    systemMessages: [{ content: '<script>unsafe</script>' }], openSockets: {},
    login_support_title: '', login_support_text: '', process: { env: { OAUTH2_ENABLED: 'true', OAUTH2_PROVIDER: 'Institution', ALLOW_EMAIL_LOGIN: 'true' } },
  }
  for (const name of ['login.pug', 'admin-index.pug', 'admin-sysadmin.pug']) {
    const source = read(name).replace(/^extends .*\n/m, '').replace(/^include .*\n/gm, '')
    const html = pug.render(mixins + source, locals)
    if (name === 'login.pug') {
      assert.match(html, /type="text" name="email"/)
      assert.match(html, /Log in via Institution/)
      assert.doesNotMatch(pug.render(mixins + source, { ...locals, process: { env: {} } }), /oauth\/redirect/)
    } else {
      assert.match(html, /href="\/admin\/register"/)
      assert.match(html, /&lt;script&gt;unsafe&lt;\/script&gt;/)
      assert.match(html, /value="csrf"/)
    }
  }
})

test('OAuth login renders exactly the configured password fallback modes', { skip: !process.env.PUG_MODULE_PATH }, () => {
  const pug = require(process.env.PUG_MODULE_PATH)
  const mixins = ['formMessagesNewStyle', 'customFormMessageNewStyle']
    .map(name => `mixin ${name}()\n\tblock\n`).join('')
  const source = read('login.pug').replace(/^extends .*\n/m, '')
  for (const [local, ldap] of [[false, false], [true, false], [false, true], [true, true]]) {
    const html = pug.render(mixins + source, {
      translate: value => value, csrfToken: 'csrf', login_support_title: '', login_support_text: '',
      process: { env: {
        OAUTH2_ENABLED: 'true', OAUTH2_PROVIDER: 'Institution',
        ALLOW_EMAIL_LOGIN: String(local), ALLOW_LDAP_LOGIN: String(ldap), LDAP_SERVER: 'ldaps://directory.test',
      } },
    })
    assert.match(html, /href="\/oauth\/redirect"/)
    assert.equal(html.includes('action="/login"'), local || ldap)
    assert.equal(html.includes('type="password"'), local || ldap)
    assert.equal(html.includes('href="/user/password/reset"'), local)
  }
})