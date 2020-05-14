/* eslint-disable
    camelcase,
    max-len,
    no-unused-vars,
*/
// TODO: This file was created by bulk-decaffeinate.
// Fix any style issues and re-enable lint.
/*
 * decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
let ContactsController
const AuthenticationController = require('../Authentication/AuthenticationController')
const ContactManager = require('./ContactManager')
const UserGetter = require('../User/UserGetter')
const logger = require('logger-sharelatex')
const Modules = require('../../infrastructure/Modules')
const { Client } = require('ldapts');

module.exports = ContactsController = {
  getContacts(req, res, next) {
    const user_id = AuthenticationController.getLoggedInUserId(req)
    return ContactManager.getContactIds(user_id, { limit: 50 }, function(
      error,
      contact_ids
    ) {
      if (error != null) {
        return next(error)
      }
      return UserGetter.getUsers(
        contact_ids,
        {
          email: 1,
          first_name: 1,
          last_name: 1,
          holdingAccount: 1
        },
        function(error, contacts) {
          if (error != null) {
            return next(error)
          }

          // UserGetter.getUsers may not preserve order so put them back in order
          const positions = {}
          for (let i = 0; i < contact_ids.length; i++) {
            const contact_id = contact_ids[i]
            positions[contact_id] = i
          }
	  
          contacts.sort(
            (a, b) =>
              positions[a._id != null ? a._id.toString() : undefined] -
              positions[b._id != null ? b._id.toString() : undefined]
          )

          // Don't count holding accounts to discourage users from repeating mistakes (mistyped or wrong emails, etc)
          contacts = contacts.filter(c => !c.holdingAccount)
	  ContactsController.getLdapContacts(contacts).then((ldapcontacts) => { 
	    contacts.push(ldapcontacts)
            contacts = contacts.map(ContactsController._formatContact)
            return Modules.hooks.fire('getContacts', user_id, contacts, function(
              error,
              additional_contacts
            ) {
              if (error != null) {
                return next(error)
              }
              contacts = contacts.concat(...Array.from(additional_contacts || []))
              return res.send({
                contacts
              })
            })
  	  }).catch(e => console.log("Error appending ldap contacts" + e))

        }
      )
    })
  },
  async getLdapContacts(contacts) {
    if (! process.env.LDAP_CONTACTS) {
       return contacts
    }
    const client = new Client({
    url: process.env.LDAP_SERVER,
    });
    const ldap_base = process.env.LDAP_BASE
    // get user data
    try {
      const {searchEntries,searchReferences,} = await client.search(ldap_base, {scope: 'sub',filter: process.env.LDAP_GROUP_FILTER ,});
      await searchEntries;
      for (var i = 0; i < searchEntries.length; i++) {
       var entry = new Map()
       var obj = searchEntries[i];
       entry['_id'] = undefined
       entry['email'] = obj['mail']
       entry['first_name'] = obj['givenName']
       entry['last_name'] = obj['sn']
       entry['type'] = "user"
       contacts.push(entry)
      }
    } catch (ex) {
      console.log(String(ex))
    }  
    //console.log(JSON.stringify(contacts)) 
    finally {
     // even if we did not use bind - the constructor of 
     // new Client() opens a socket to the ldap server
     client.unbind()
     return contacts
    }
  },
  _formatContact(contact) {
    return {
      id: contact._id != null ? contact._id.toString() : undefined,
      email: contact.email || '',
      first_name: contact.first_name || '',
      last_name: contact.last_name || '',
      type: 'user'
    }
  }
}
