const SessionManager = require('../Authentication/SessionManager')
const ContactManager = require('./ContactManager')
const UserGetter = require('../User/UserGetter')
const Modules = require('../../infrastructure/Modules')
const { expressify } = require('@overleaf/promise-utils')

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// TODO(ldap)
//const { Client } = require('ldapts')
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

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

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  // TODO(ldap)
  //const ldapcontacts = getLdapContacts(contacts)
  //contacts.push(ldapcontacts)
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

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

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// TODO(ldap)
// async function getLdapContacts(contacts) {
//   if (
//     process.env.LDAP_CONTACTS === undefined ||
//     !(process.env.LDAP_CONTACTS.toLowerCase() === 'true')
//   ) {
//     return contacts
//   }
//   const client = new Client({
//     url: process.env.LDAP_SERVER,
//   })

//   // if we need a ldap user try to bind
//   if (process.env.LDAP_BIND_USER) {
//     try {
//       await client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PW)
//     } catch (ex) {
//       console.log('Could not bind LDAP reader user: ' + String(ex))
//     }
//   }

//   const ldap_base = process.env.LDAP_BASE
//   // get user data
//   try {
//     // if you need an client.bind do it here.
//     const { searchEntries, searchReferences } = await client.search(ldap_base, {
//       scope: 'sub',
//       filter: process.env.LDAP_CONTACT_FILTER,
//     })
//     await searchEntries
//     for (var i = 0; i < searchEntries.length; i++) {
//       var entry = new Map()
//       var obj = searchEntries[i]
//       entry['_id'] = undefined
//       entry['email'] = obj['mail']
//       entry['first_name'] = obj['givenName']
//       entry['last_name'] = obj['sn']
//       entry['type'] = 'user'
//       // Only add to contacts if entry is not there.
//       if (contacts.indexOf(entry) === -1) {
//         contacts.push(entry)
//       }
//     }
//   } catch (ex) {
//     console.log(String(ex))
//   } finally {
//     // console.log(JSON.stringify(contacts))
//     // even if we did not use bind - the constructor of
//     // new Client() opens a socket to the ldap server
//     client.unbind()
//     return contacts
//   }
// }
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

module.exports = {
  getContacts: expressify(getContacts),
}
