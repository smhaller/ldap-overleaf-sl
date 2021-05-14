const Settings = require('settings-sharelatex')
const { User } = require('../../models/User')
const { db, ObjectId } = require('../../infrastructure/mongodb')
const bcrypt = require('bcrypt')
const EmailHelper = require('../Helpers/EmailHelper')
const {
  InvalidEmailError,
  InvalidPasswordError
} = require('./AuthenticationErrors')
const util = require('util')

const { Client } = require('ldapts');
const ldapEscape = require('ldap-escape');

// https://www.npmjs.com/package/@overleaf/o-error
// have a look if we can do nice error messages.

const BCRYPT_ROUNDS = Settings.security.bcryptRounds || 12
const BCRYPT_MINOR_VERSION = Settings.security.bcryptMinorVersion || 'a'

const _checkWriteResult = function(result, callback) {
  // for MongoDB
  if (result && result.modifiedCount === 1) {
    callback(null, true)
  } else {
    callback(null, false)
  }
}

const AuthenticationManager = {
  authenticate(query, password, callback) {
    // Using Mongoose for legacy reasons here. The returned User instance
    // gets serialized into the session and there may be subtle differences
    // between the user returned by Mongoose vs mongodb (such as default values)
    User.findOne(query, (error, user) => {
      //console.log("Begining:" + JSON.stringify(query))
      AuthenticationManager.authUserObj(error, user, query, password, callback)
    })
  },
    //login with any password
  login(user, password, callback) {
    AuthenticationManager.checkRounds(
      user,
      user.hashedPassword,
      password,
      function (err) {
        if (err) {
          return callback(err)
        }
        callback(null, user)
        }
    )
  },

  createIfNotExistAndLogin(query, user, callback, uid, firstname, lastname, mail, isAdmin) {
    if (!user) {
      //console.log("Creating User:" + JSON.stringify(query))
      //create random pass for local userdb, does not get checked for ldap users during login
      let pass = require("crypto").randomBytes(32).toString("hex")
      //console.log("Creating User:" + JSON.stringify(query) + "Random Pass" + pass)

      const userRegHand = require('../User/UserRegistrationHandler.js')
      userRegHand.registerNewUser({
        email: mail,
        first_name: firstname,
        last_name: lastname,
        password: pass
      },
      function (error, user) {
        if (error) {
          console.log(error)
        }
        user.email = mail
        user.isAdmin = isAdmin
        user.emails[0].confirmedAt = Date.now()
        user.save()
        //console.log("user %s added to local library: ", mail)
        User.findOne(query, (error, user) => {
          if (error) {
            console.log(error)
          }
          if (user && user.hashedPassword) {
            AuthenticationManager.login(user, "randomPass", callback)
          }
        })
      }) // end register user
    } else {
      AuthenticationManager.login(user, "randomPass", callback)
    }
  },

  authUserObj(error, user, query, password, callback) {
    if ( process.env.ALLOW_EMAIL_LOGIN && user && user.hashedPassword) {
        console.log("email login for existing user " + query.email)
        // check passwd against local db
        bcrypt.compare(password, user.hashedPassword, function (error, match) {
          if (match) {
            console.log("Local user password match")
            AuthenticationManager.login(user, password, callback)
          } else {
            console.log("Local user password mismatch, trying LDAP")
            // check passwd against ldap
            AuthenticationManager.ldapAuth(query, password, AuthenticationManager.createIfNotExistAndLogin, callback, user)
          }
        })
    } else {
      // No local passwd check user has to be in ldap and use ldap credentials
      AuthenticationManager.ldapAuth(query, password, AuthenticationManager.createIfNotExistAndLogin, callback, user)
    }
    return null
  },

  validateEmail(email) {
    // we use the emailadress from the ldap 
    // therefore we do not enforce checks here
    const parsed = EmailHelper.parseEmail(email)
    //if (!parsed) {
    //    return new InvalidEmailError({ message: 'email not valid' })
    //}
    return null
  },

  // validates a password based on a similar set of rules to `complexPassword.js` on the frontend
  // note that `passfield.js` enforces more rules than this, but these are the most commonly set.
  // returns null on success, or an error object.
  validatePassword(password, email) {
    if (password == null) {
      return new InvalidPasswordError({
        message: 'password not set',
        info: { code: 'not_set' }
      })
    }

    let allowAnyChars, min, max
    if (Settings.passwordStrengthOptions) {
      allowAnyChars = Settings.passwordStrengthOptions.allowAnyChars === true
      if (Settings.passwordStrengthOptions.length) {
        min = Settings.passwordStrengthOptions.length.min
        max = Settings.passwordStrengthOptions.length.max
      }
    }
    allowAnyChars = !!allowAnyChars
    min = min || 6
    max = max || 72

    // we don't support passwords > 72 characters in length, because bcrypt truncates them
    if (max > 72) {
      max = 72
    }

    if (password.length < min) {
      return new InvalidPasswordError({
        message: 'password is too short',
        info: { code: 'too_short' }
      })
    }
    if (password.length > max) {
      return new InvalidPasswordError({
        message: 'password is too long',
        info: { code: 'too_long' }
      })
    }
    if (
      !allowAnyChars &&
      !AuthenticationManager._passwordCharactersAreValid(password)
    ) {
      return new InvalidPasswordError({
        message: 'password contains an invalid character',
        info: { code: 'invalid_character' }
      })
      }
      return null
    },

  setUserPassword(user, password, callback) {
    AuthenticationManager.setUserPasswordInV2(user, password, callback)
  },

  checkRounds(user, hashedPassword, password, callback) {
    // Temporarily disable this function, TODO: re-enable this
    //return callback()
    if (Settings.security.disableBcryptRoundsUpgrades) {
      return callback()
    }
    // check current number of rounds and rehash if necessary
    const currentRounds = bcrypt.getRounds(hashedPassword)
    if (currentRounds < BCRYPT_ROUNDS) {
      AuthenticationManager.setUserPassword(user, password, callback)
    } else {
      callback()
    }
  },

  hashPassword(password, callback) {
    bcrypt.genSalt(BCRYPT_ROUNDS, BCRYPT_MINOR_VERSION, function(error, salt) {
      if (error) {
        return callback(error)
      }
      bcrypt.hash(password, salt, callback)
    })
  },

  setUserPasswordInV2(user, password, callback) {
    //if (!user || !user.email || !user._id) {
    //  return callback(new Error('invalid user object'))
    //}
    
    console.log("Setting pass for user: " + JSON.stringify(user))
    const validationError = this.validatePassword(password, user.email)
    if (validationError) {
      return callback(validationError)
    }
    this.hashPassword(password, function(error, hash) {
      if (error) {
        return callback(error)
      }
      db.users.updateOne(
        {
          _id: ObjectId(user._id.toString())
        },
        {
          $set: {
            hashedPassword: hash
          },
          $unset: {
            password: true
          }
        },
        function(updateError, result) {
          if (updateError) {
            return callback(updateError)
          }
          _checkWriteResult(result, callback)
        }
      )
    })
  },

  _passwordCharactersAreValid(password) {
    let digits, letters, lettersUp, symbols
    if (
      Settings.passwordStrengthOptions &&
      Settings.passwordStrengthOptions.chars
    ) {
      digits = Settings.passwordStrengthOptions.chars.digits
      letters = Settings.passwordStrengthOptions.chars.letters
      lettersUp = Settings.passwordStrengthOptions.chars.letters_up
      symbols = Settings.passwordStrengthOptions.chars.symbols
    }
    digits = digits || '1234567890'
    letters = letters || 'abcdefghijklmnopqrstuvwxyz'
    lettersUp = lettersUp || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    symbols = symbols || '@#$%^&*()-_=+[]{};:<>/?!£€.,'

    for (let charIndex = 0; charIndex <= password.length - 1; charIndex++) {
      if (
        digits.indexOf(password[charIndex]) === -1 &&
        letters.indexOf(password[charIndex]) === -1 &&
        lettersUp.indexOf(password[charIndex]) === -1 &&
        symbols.indexOf(password[charIndex]) === -1
      ) {
        return false
      }
    }
    return true
  },

  async ldapAuth(query, password, onSuccessCreateUserIfNotExistent, callback, user) {
    const client = new Client({
      url: process.env.LDAP_SERVER,
    });
    //const bindDn = process.env.LDAP_BIND_USER
    //const bindPassword = process.env.LDAP_BIND_PW
    const ldap_reader = process.env.LDAP_BIND_USER
    const ldap_reader_pass = process.env.LDAP_BIND_PW
    const ldap_base = process.env.LDAP_BASE
    var mail = query.email
    var uid = query.email.split('@')[0]
    //const filterstr = '(&' + process.env.LDAP_GROUP_FILTER + '(' + ldapEscape.filter`uid=${uid}` + '))'
    const filterstr = '(&' + process.env.LDAP_GROUP_FILTER + '(' + ldapEscape.filter`mail=${mail}` + '))'
    var userDn = "" // 'uid=' + uid + ',' + ldap_bd;
    var firstname = ""
    var lastname = ""
    var uid = ""
    var isAdmin = false
    // check bind
    try {
      await client.bind(ldap_reader, ldap_reader_pass);
      //await client.bind(userDn,password);
    } catch (ex) {
      console.log("Could not bind LDAP reader: " + ldap_reader + " err: " + String(ex))
      return callback(null, null)
    }
    // get user data
    try {
      const {searchEntries, searchRef,} = await client.search(ldap_base, {
        scope: 'sub',
        filter: filterstr ,
      });
      await searchEntries
      console.log(JSON.stringify(searchEntries))
      if (searchEntries[0]) {
        mail = searchEntries[0].mail
        uid = searchEntries[0].uid
        firstname = searchEntries[0].givenName
        lastname = searchEntries[0].sn
        userDn = searchEntries[0].dn
        console.log("Found user: " + mail + " Name: " + firstname + " " + lastname + " DN: " + userDn)
      }
    } catch (ex) {
      console.log("An Error occured while getting user data during ldapsearch: " + String(ex))
        await client.unbind();
        return callback(null, null)
    }

    try {
      // if admin filter is set - only set admin for user in ldap group
      // does not matter - admin is deactivated: managed through ldap
      if (process.env.LDAP_ADMIN_GROUP_FILTER) { 
        const adminfilter = '(&' + process.env.LDAP_ADMIN_GROUP_FILTER + '(' +ldapEscape.filter`uid=${uid}` + '))'
        adminEntry = await client.search(ldap_base, {
          scope: 'sub',
          filter: adminfilter,
        });
        await adminEntry;
        //console.log("Admin Search response:" + JSON.stringify(adminEntry.searchEntries))
        if (adminEntry.searchEntries[0].mail) {
          console.log("is Admin")
          isAdmin=true;
        }
      }
    } catch (ex) {
      console.log("An Error occured while checking for admin rights - setting admin rights to false: " + String(ex))
      isAdmin = false;
    } finally {
      await client.unbind();
    }
    if (mail == "" || userDn == "") {
      console.log("Mail / userDn not set - exit. This should not happen - please set mail-entry in ldap.")
      return callback(null, null)
    }
    try {
      await client.bind(userDn, password);
    } catch (ex) {
      console.log("Could not bind User: " + userDn + " err: " + String(ex))
      return callback(null, null)
    } finally {
      await client.unbind()
    }

    //console.log("Logging in user: " + mail + " Name: " + firstname + " " + lastname + " isAdmin: " + String(isAdmin))
    // we are authenticated now let's set the query to the correct mail from ldap
    query.email = mail
    User.findOne(query, (error, user) => {
      if (error) {
        console.log(error)
      }
      if (user && user.hashedPassword) {
        //console.log("******************** LOGIN ******************")
        AuthenticationManager.login(user, "randomPass", callback)
      } else {
        onSuccessCreateUserIfNotExistent(query, user, callback, uid, firstname, lastname, mail, isAdmin)
      }
    })
  }
}

AuthenticationManager.promises = {
  authenticate: util.promisify(AuthenticationManager.authenticate),
  hashPassword: util.promisify(AuthenticationManager.hashPassword),
  setUserPassword: util.promisify(AuthenticationManager.setUserPassword)
}

module.exports = AuthenticationManager
