const ChatApiHandler = require('../Chat/ChatApiHandler')
const ChatManager = require('../Chat/ChatManager')
const EditorRealTimeController = require('../Editor/EditorRealTimeController')
const SessionManager = require('../Authentication/SessionManager')
const UserInfoManager = require('../User/UserInfoManager')
const UserInfoController = require('../User/UserInfoController')
const DocstoreManager = require('../Docstore/DocstoreManager')
const DocumentUpdaterHandler = require('../DocumentUpdater/DocumentUpdaterHandler')
const CollaboratorsGetter = require('../Collaborators/CollaboratorsGetter')
const { Project } = require('../../models/Project')

function requestError(message, status = 400) {
  return Object.assign(new Error(message), { status })
}

function loggedInUserId(req) {
  const userId = SessionManager.getLoggedInUserId(req.session)
  if (userId == null) throw requestError('no logged-in user', 401)
  return userId
}

async function projectRanges(projectId) {
  await DocumentUpdaterHandler.promises.flushProjectToMongo(projectId)
  return DocstoreManager.promises.getAllRanges(projectId)
}

const handlers = {
  async trackChanges(req, res) {
    const { project_id: projectId } = req.params
    const { on, on_for: onFor, on_for_guests: onForGuests } = req.body
    if (on !== undefined && typeof on !== 'boolean') throw requestError('on must be a boolean')
    if (onForGuests !== undefined && typeof onForGuests !== 'boolean') throw requestError('on_for_guests must be a boolean')
    if (onFor !== undefined && (
      onFor === null || typeof onFor !== 'object' || Array.isArray(onFor) ||
      Object.entries(onFor).some(([userId, enabled]) =>
        !/^(?:[a-f\d]{24}|__guests__)$/.test(userId) || typeof enabled !== 'boolean'
      )
    )) throw requestError('on_for must map user IDs to booleans')
    if (on === undefined && onFor === undefined && onForGuests === undefined) throw requestError('missing track changes state')
    let state = on === true ? true : onFor !== undefined ? { ...onFor } : on ?? false
    if (onForGuests !== undefined && state !== true) {
      if (typeof state !== 'object') state = {}
      state.__guests__ = onForGuests
    }
    await Project.updateOne({ _id: projectId }, { $set: { track_changes: state } }).exec()
    EditorRealTimeController.emitToRoom(projectId, 'toggle-track-changes', state)
    res.sendStatus(204)
  },
  async acceptChanges(req, res) {
    const { project_id: projectId, doc_id: docId } = req.params
    const { change_ids: changeIds } = req.body
    if (!Array.isArray(changeIds) || changeIds.some(changeId => typeof changeId !== 'string')) throw requestError('change_ids must be an array of strings')
    await DocumentUpdaterHandler.promises.acceptChanges(projectId, docId, changeIds)
    EditorRealTimeController.emitToRoom(projectId, 'accept-changes', docId, changeIds)
    res.sendStatus(204)
  },
  async getAllRanges(req, res) {
    const ranges = await projectRanges(req.params.project_id)
    res.json(ranges.map(({ _id, id, ...range }) => ({ ...range, id: String(id ?? _id) })))
  },
  async getChangesUsers(req, res) {
    const projectId = req.params.project_id
    const memberIds = await CollaboratorsGetter.promises.getMemberIds(projectId)
    const ranges = await projectRanges(projectId)
    const userIds = new Set(memberIds.map(String))
    for (const doc of ranges) {
      for (const change of doc.ranges?.changes || []) {
        if (change.metadata?.user_id != null) userIds.add(String(change.metadata.user_id))
      }
    }
    const users = []
    for (const userId of userIds) {
      const user = await UserInfoManager.promises.getPersonalInfo(userId)
      if (user) users.push(UserInfoController.formatPersonalInfo(user))
    }
    users.push({ id: null })
    res.json(users)
  },
  async getThreads(req, res) {
    const threads = await ChatApiHandler.promises.getThreads(req.params.project_id)
    await ChatManager.promises.injectUserInfoIntoThreads(threads)
    res.json(threads)
  },
  async sendComment(req, res) {
    const { project_id: projectId, thread_id: threadId } = req.params
    const userId = loggedInUserId(req)
    const message = await ChatApiHandler.promises.sendComment(projectId, threadId, userId, req.body.content)
    const user = await UserInfoManager.promises.getPersonalInfo(userId)
    message.user = UserInfoController.formatPersonalInfo(user)
    EditorRealTimeController.emitToRoom(projectId, 'new-comment', threadId, message)
    res.sendStatus(204)
  },
  async editMessage(req, res) {
    const { project_id: projectId, thread_id: threadId, message_id: messageId } = req.params
    await ChatApiHandler.promises.editMessage(projectId, threadId, messageId, loggedInUserId(req), req.body.content)
    EditorRealTimeController.emitToRoom(projectId, 'edit-message', threadId, messageId, req.body.content)
    res.sendStatus(204)
  },
  async deleteMessage(req, res) {
    const { project_id: projectId, thread_id: threadId, message_id: messageId } = req.params
    loggedInUserId(req)
    await ChatApiHandler.promises.deleteMessage(projectId, threadId, messageId)
    EditorRealTimeController.emitToRoom(projectId, 'delete-message', threadId, messageId)
    res.sendStatus(204)
  },
  async resolveThread(req, res) {
    const { project_id: projectId, doc_id: docId, thread_id: threadId } = req.params
    const userId = loggedInUserId(req)
    if (docId != null) await DocumentUpdaterHandler.promises.resolveThread(projectId, docId, threadId, userId)
    await ChatApiHandler.promises.resolveThread(projectId, threadId, userId)
    EditorRealTimeController.emitToRoom(projectId, 'resolve-thread', threadId, userId)
    res.sendStatus(204)
  },
  async reopenThread(req, res) {
    const { project_id: projectId, doc_id: docId, thread_id: threadId } = req.params
    await DocumentUpdaterHandler.promises.reopenThread(projectId, docId, threadId, loggedInUserId(req))
    await ChatApiHandler.promises.reopenThread(projectId, threadId)
    EditorRealTimeController.emitToRoom(projectId, 'reopen-thread', threadId)
    res.sendStatus(204)
  },
  async deleteThread(req, res) {
    const { project_id: projectId, doc_id: docId, thread_id: threadId } = req.params
    await DocumentUpdaterHandler.promises.deleteThread(projectId, docId, threadId, loggedInUserId(req))
    await ChatApiHandler.promises.deleteThread(projectId, threadId)
    EditorRealTimeController.emitToRoom(projectId, 'delete-thread', threadId)
    res.sendStatus(204)
  },
}

module.exports = Object.fromEntries(
  Object.entries(handlers).map(([name, handler]) => [
    name,
    (req, res, next) => handler(req, res).catch(next),
  ])
)
