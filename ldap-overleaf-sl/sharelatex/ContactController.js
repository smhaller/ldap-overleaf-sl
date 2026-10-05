import SessionManager from '../Authentication/SessionManager.js'
import ContactManager from './ContactManager.js'
import UserGetter from '../User/UserGetter.js'
import Modules from '../../infrastructure/Modules.js'
import { expressify } from '@overleaf/promise-utils'
import fs from 'node:fs'
import { Client } from 'ldapts'

function _formatContact(contact) {
  return {
    id: contact._id?.toString(),
    email: contact.email || '',
    first_name: contact.first_name || '',
    last_name: contact.last_name || '',
    type: 'user',
  }
}

async function getContacts(req, res) {
  const userId = SessionManager.getLoggedInUserId(req.session)

  const contactIds = await ContactManager.promises.getContactIds(userId, {
    limit: 50,
  })

  let contacts = await UserGetter.promises.getUsers(contactIds, {
    email: 1,
    first_name: 1,
    last_name: 1,
    holdingAccount: 1,
  })

  // UserGetter.getUsers may not preserve order so put them back in order
  const positions = {}
  for (let i = 0; i < contactIds.length; i++) {
    const contactId = contactIds[i]
    positions[contactId] = i
  }
  contacts.sort(
    (a, b) => positions[a._id?.toString()] - positions[b._id?.toString()]
  )

  // Don't count holding accounts to discourage users from repeating mistakes (mistyped or wrong emails, etc)
  contacts = contacts.filter(c => !c.holdingAccount)

  contacts = await getLdapContacts(contacts)

  contacts = contacts.map(_formatContact)

  const additionalContacts = await Modules.promises.hooks.fire(
    'getContacts',
    userId,
    contacts
  )

  contacts = contacts.concat(...(additionalContacts || []))
  return res.json({
    contacts,
  })
}

async function getLdapContacts(contacts) {
  if (process.env.LDAP_CONTACTS?.toLowerCase() !== 'true') {
    return contacts
  }

  let client
  let result = contacts
  try {
    const options = { url: process.env.LDAP_SERVER }
    if (
      process.env.LDAP_SERVER_CACERT &&
      fs.existsSync(process.env.LDAP_SERVER_CACERT)
    ) {
      options.tlsOptions = {
        ca: [fs.readFileSync(process.env.LDAP_SERVER_CACERT)],
      }
    }
    client = new Client(options)
    if (process.env.LDAP_BIND_USER) {
      await client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PW)
    }
    const { searchEntries } = await client.search(process.env.LDAP_BASE, {
      scope: 'sub',
      filter: process.env.LDAP_CONTACT_FILTER,
    })
    const seen = new Set(
      contacts
        .filter(contact => typeof contact.email === 'string')
        .map(contact => contact.email.trim().toLowerCase())
    )
    const additions = []
    const attribute = value =>
      (Array.isArray(value) ? value : [value]).find(
        item => typeof item === 'string'
      ) || ''
    for (const entry of searchEntries) {
      const emails = Array.isArray(entry.mail) ? entry.mail : [entry.mail]
      for (const mail of emails) {
        if (typeof mail !== 'string' || !mail.trim()) {
          continue
        }
        const email = mail.trim()
        const key = email.toLowerCase()
        if (seen.has(key)) {
          continue
        }
        seen.add(key)
        additions.push({
          email,
          first_name: attribute(entry.givenName),
          last_name: attribute(entry.sn),
        })
      }
    }
    result = contacts.concat(additions)
  } catch (error) {
    console.error('Could not load LDAP contacts:', error)
  } finally {
    if (client) {
      try {
        await client.unbind()
      } catch (error) {
        console.error('Could not unbind LDAP contacts client:', error)
        result = contacts
      }
    }
  }
  return result
}

export default {
  getContacts: expressify(getContacts),
}
