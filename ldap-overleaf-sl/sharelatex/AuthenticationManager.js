const Settings = require('@overleaf/settings')
const { User } = require('../../models/User')
const { db, ObjectId } = require('../../infrastructure/mongodb')
const bcrypt = require('bcrypt')
const EmailHelper = require('../Helpers/EmailHelper')
const {
  InvalidEmailError,
  InvalidPasswordError,
  ParallelLoginError,
  PasswordMustBeDifferentError,
  PasswordReusedError,
} = require('./AuthenticationErrors')
const {
  callbackify,
  callbackifyMultiResult,
} = require('@overleaf/promise-utils')
const HaveIBeenPwned = require('./HaveIBeenPwned')
const UserAuditLogHandler = require('../User/UserAuditLogHandler')
const logger = require('@overleaf/logger')
const DiffHelper = require('../Helpers/DiffHelper')
const Metrics = require('@overleaf/metrics')

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// TODO(ldap)
// const fs = require("fs")
// const { Client } = require("ldapts")
// const ldapEscape = require("ldap-escape")
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

const BCRYPT_ROUNDS = Settings.security.bcryptRounds || 12
const BCRYPT_MINOR_VERSION = Settings.security.bcryptMinorVersion || 'a'
const MAX_SIMILARITY = 0.7

function _exceedsMaximumLengthRatio(password, maxSimilarity, value) {
  const passwordLength = password.length
  const lengthBoundSimilarity = (maxSimilarity / 2) * passwordLength
  const valueLength = value.length
  return (
    passwordLength >= 10 * valueLength && valueLength < lengthBoundSimilarity
  )
}

const _checkWriteResult = function (result) {
  // for MongoDB
  return !!(result && result.modifiedCount === 1)
}

function _validatePasswordNotTooLong(password) {
  // bcrypt has a hard limit of 72 characters.
  if (password.length > 72) {
    return new InvalidPasswordError({
      message: 'password is too long',
      info: { code: 'too_long' },
    })
  }
  return null
}

function _metricsForSuccessfulPasswordMatch(password) {
  const validationResult = AuthenticationManager.validatePassword(password)
  const status =
    validationResult === null ? 'success' : validationResult?.info?.code
  Metrics.inc('check-password', { status })
  return null
}

const AuthenticationManager = {
  async _checkUserPassword(query, password) {
    // Using Mongoose for legacy reasons here. The returned User instance
    // gets serialized into the session and there may be subtle differences
    // between the user returned by Mongoose vs mongodb (such as default values)
    const user = await User.findOne(query).exec()

    if (!user || !user.hashedPassword) {
      return { user: null, match: null }
    }

    let rounds = 0
    try {
      rounds = bcrypt.getRounds(user.hashedPassword)
    } catch (err) {
      let prefix, suffix, length
      if (typeof user.hashedPassword === 'string') {
        length = user.hashedPassword.length
        if (user.hashedPassword.length > 50) {
          // A full bcrypt hash is 60 characters long.
          prefix = user.hashedPassword.slice(0, '$2a$12$x'.length)
          suffix = user.hashedPassword.slice(-4)
        } else if (user.hashedPassword.length > 20) {
          prefix = user.hashedPassword.slice(0, 4)
          suffix = user.hashedPassword.slice(-4)
        } else {
          prefix = user.hashedPassword.slice(0, 4)
        }
      }
      logger.warn(
        {
          err,
          userId: user._id,
          hashedPassword: {
            type: typeof user.hashedPassword,
            length,
            prefix,
            suffix,
          },
        },
        'unexpected user.hashedPassword value'
      )
    }
    Metrics.inc('bcrypt', 1, {
      method: 'compare',
      path: rounds,
    })

    const match = await bcrypt.compare(password, user.hashedPassword)

    if (match) {
      _metricsForSuccessfulPasswordMatch(password)
    }

    return { user, match }
  },

  // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  async _checkUserPassword2(query, password) {
    // leave original _checkUserPassword untouched, because it will be called by
    // setUserPasswordInV2 (e.g. UserRegistrationHandler.js )
    const user = await User.findOne(query).exec()

    return await AuthenticationManager.authUserObj(user, query, password)
  },
  // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

  async authenticate(query, password, auditLog, { enforceHIBPCheck = true }) {
    // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    const { user, match } = await AuthenticationManager._checkUserPassword2(
      // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<      
      query,
      password
    )

    if (!user) {
      return { user: null }
    }

    const update = { $inc: { loginEpoch: 1 } }
    if (!match) {
      update.$set = { lastFailedLogin: new Date() }
    }

    const result = await User.updateOne(
      { _id: user._id, loginEpoch: user.loginEpoch },
      update,
      {}
    ).exec()

    if (result.modifiedCount !== 1) {
      throw new ParallelLoginError()
    }

    if (!match) {
      if (!auditLog) {
        return { user: null }
      } else {
        try {
          await UserAuditLogHandler.promises.addEntry(
            user._id,
            'failed-password-match',
            user._id,
            auditLog.ipAddress,
            auditLog.info
          )
        } catch (err) {
          logger.error(
            { userId: user._id, err, info: auditLog.info },
            'Error while adding AuditLog entry for failed-password-match'
          )
        }
        return { user: null }
      }
    }
    await AuthenticationManager.checkRounds(user, user.hashedPassword, password)

    let isPasswordReused
    try {
      isPasswordReused =
        await HaveIBeenPwned.promises.checkPasswordForReuse(password)
    } catch (err) {
      logger.err({ err }, 'cannot check password for re-use')
    }

    if (isPasswordReused && enforceHIBPCheck) {
      throw new PasswordReusedError()
    }

    return { user, isPasswordReused }
  },


  // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 
  async createIfNotFoundAndLogin(
    query,
    uid,
    firstname,
    lastname,
    mail,
    isAdmin
  ) {
    const user = await User.findOne(query).exec()
    
    return await AuthenticationManager.createIfNotExistAndLogin(
      query,
      user,
      uid,
      firstname,
      lastname,
      mail,
      isAdmin
    )
  },

  async createIfNotExistAndLogin(
    query,
    user,
    uid,
    firstname,
    lastname,
    mail,
    isAdmin
  ) {
    if (!user) {
      //create random pass for local userdb, does not get checked for ldap users during login
      const pass = require("crypto").randomBytes(32).toString("hex")
      console.log('Creating User', { mail, uid, firstname, lastname, isAdmin, pass })

      const userRegHand = require("../User/UserRegistrationHandler.js")
      const createdUser = await userRegHand.promises.registerNewUser(
        {
          email: mail,
          first_name: firstname,
          last_name: lastname,
          password: pass,
        }
      ) // end register user   
      return { user: createdUser, match: true }  
    } else {
      console.log('User exists', { mail })
      return { user: user, match: true }
    }
  },

  async authUserObj(user, query, password) {
    if (process.env.ALLOW_EMAIL_LOGIN && user && user.hashedPassword) {
      console.log("email login for existing user " + query.email)
      // check passwd against local db
      const match = await bcrypt.compare(password, user.hashedPassword)
        if (match) {
          console.log("Local user password match")
          _metricsForSuccessfulPasswordMatch(password)
          return { user, match }
        } else {
          console.log("Local user password mismatch, trying LDAP")
          // check passwd against ldap
          // TODO(ldap)
          return { user: null, match: null }
          // return AuthenticationManager.ldapAuth(
          //   query,
          //   password,
          //   AuthenticationManager.createIfNotExistAndLogin,
          //   user
          // )
        }
      
    } else {
      // No local passwd check user has to be in ldap and use ldap credentials
      // TODO(ldap)
      return { user: null, match: null }
      // return AuthenticationManager.ldapAuth(
      //   query,
      //   password,
      //   AuthenticationManager.createIfNotExistAndLogin,
      //   user
      // )
    }
  },

  // TODO(ldap)
  // async ldapAuth(
  //   query,
  //   password,
  //   onSuccessCreateUserIfNotExistent,
  //   user
  // ) {
  //   const client = fs.existsSync(process.env.LDAP_SERVER_CACERT)
  //     ? new Client({
  //       url: process.env.LDAP_SERVER,
  //       tlsOptions: {
  //         ca: [fs.readFileSync(process.env.LDAP_SERVER_CACERT)],
  //       },
  //     })
  //     : new Client({
  //       url: process.env.LDAP_SERVER,
  //     })

  //   const ldap_reader = process.env.LDAP_BIND_USER
  //   const ldap_reader_pass = process.env.LDAP_BIND_PW
  //   const ldap_base = process.env.LDAP_BASE

  //   var mail = query.email
  //   var uid = query.email.split("@")[0]
  //   var firstname = ""
  //   var lastname = ""
  //   var isAdmin = false
  //   var userDn = ""

  //   //replace all appearences of %u with uid and all %m with mail:
  //   const replacerUid = new RegExp("%u", "g")
  //   const replacerMail = new RegExp("%m", "g")
  //   const filterstr = process.env.LDAP_USER_FILTER.replace(
  //     replacerUid,
  //     ldapEscape.filter`${uid}`
  //   ).replace(replacerMail, ldapEscape.filter`${mail}`) //replace all appearances
  //   // check bind
  //   try {
  //     if (process.env.LDAP_BINDDN) {
  //       //try to bind directly with the user trying to log in
  //       userDn = process.env.LDAP_BINDDN.replace(
  //         replacerUid,
  //         ldapEscape.filter`${uid}`
  //       ).replace(replacerMail, ldapEscape.filter`${mail}`)
  //       await client.bind(userDn, password)
  //     } else {
  //       // use fixed bind user
  //       await client.bind(ldap_reader, ldap_reader_pass)
  //     }
  //   } catch (ex) {
  //     if (process.env.LDAP_BINDDN) {
  //       console.log("Could not bind user: " + userDn)
  //     } else {
  //       console.log(
  //         "Could not bind LDAP reader: " + ldap_reader + " err: " + String(ex)
  //       )
  //     }
  //     return { user: null, match: null }
  //   }

  //   // get user data
  //   try {
  //     const { searchEntries, searchRef } = await client.search(ldap_base, {
  //       scope: "sub",
  //       filter: filterstr,
  //     })
  //     await searchEntries
  //     console.log(JSON.stringify(searchEntries))
  //     if (searchEntries[0]) {
  //       mail = searchEntries[0].mail
  //       uid = searchEntries[0].uid
  //       firstname = searchEntries[0].givenName
  //       lastname = searchEntries[0].sn
  //       if (!process.env.LDAP_BINDDN) {
  //         //dn is already correctly assembled
  //         userDn = searchEntries[0].dn
  //       }
  //       console.log(
  //         `Found user: ${mail} Name: ${firstname} ${lastname} DN: ${userDn}`
  //       )
  //     }
  //   } catch (ex) {
  //     console.log(
  //       "An Error occured while getting user data during ldapsearch: " +
  //       String(ex)
  //     )
  //     await client.unbind()
  //     return { user: null, match: null }
  //   }

  //   try {
  //     // if admin filter is set - only set admin for user in ldap group
  //     // does not matter - admin is deactivated: managed through ldap
  //     if (process.env.LDAP_ADMIN_GROUP_FILTER) {
  //       const adminfilter = process.env.LDAP_ADMIN_GROUP_FILTER.replace(
  //         replacerUid,
  //         ldapEscape.filter`${uid}`
  //       ).replace(replacerMail, ldapEscape.filter`${mail}`)
  //       let adminEntry = await client.search(ldap_base, {
  //         scope: "sub",
  //         filter: adminfilter,
  //       })
  //       await adminEntry
  //       //console.log('Admin Search response:' + JSON.stringify(adminEntry.searchEntries))
  //       if (adminEntry.searchEntries[0]) {
  //         console.log("is Admin")
  //         isAdmin = true
  //       }
  //     }
  //   } catch (ex) {
  //     console.log(
  //       "An Error occured while checking for admin rights - setting admin rights to false: " +
  //       String(ex)
  //     )
  //     isAdmin = false
  //   } finally {
  //     await client.unbind()
  //   }
  //   if (mail == "" || userDn == "") {
  //     console.log(
  //       "Mail / userDn not set - exit. This should not happen - please set mail-entry in ldap."
  //     )
  //     return { user: null, match: null }
  //   }

  //   if (!process.env.BINDDN) {
  //     //since we used a fixed bind user to obtain the correct userDn we need to bind again to authenticate
  //     try {
  //       await client.bind(userDn, password)
  //     } catch (ex) {
  //       console.log("Could not bind User: " + userDn + " err: " + String(ex))
  //       return { user: null, match: null }
  //     } finally {
  //       await client.unbind()
  //     }
  //   }
  //   //console.log('Logging in user: ' + mail + ' Name: ' + firstname + ' ' + lastname + ' isAdmin: ' + String(isAdmin))
  //   // we are authenticated now let's set the query to the correct mail from ldap
  //   query.email = mail
  //   const createdUser = await User.findOne(query).exec()

  //   if (createdUser && createdUser.hashedPassword) {
  //     //console.log('******************** LOGIN ******************')
  //     return { user: createdUser, match: true }
  //   } else {
  //     return await onSuccessCreateUserIfNotExistent(
  //       query,
  //       createdUser,
  //       uid,
  //       firstname,
  //       lastname,
  //       mail,
  //       isAdmin
  //     )
  //   }
    
  // },
  // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  validateEmail(email) {
    const parsed = EmailHelper.parseEmail(email)
    if (!parsed) {
      return new InvalidEmailError({ message: 'email not valid' })
    }
    return null
  },

  // validates a password based on a similar set of rules previously used by `passfield.js` on the frontend
  // note that `passfield.js` enforced more rules than this, but these are the most commonly set.
  // returns null on success, or an error object.
  validatePassword(password, email) {
    if (password == null) {
      return new InvalidPasswordError({
        message: 'password not set',
        info: { code: 'not_set' },
      })
    }

    Metrics.inc('try-validate-password')

    let allowAnyChars, min, max
    if (Settings.passwordStrengthOptions) {
      allowAnyChars = Settings.passwordStrengthOptions.allowAnyChars === true
      if (Settings.passwordStrengthOptions.length) {
        min = Settings.passwordStrengthOptions.length.min
        max = Settings.passwordStrengthOptions.length.max
      }
    }
    allowAnyChars = !!allowAnyChars
    min = min || 8
    max = max || 72

    // we don't support passwords > 72 characters in length, because bcrypt truncates them
    if (max > 72) {
      max = 72
    }

    if (password.length < min) {
      return new InvalidPasswordError({
        message: 'password is too short',
        info: { code: 'too_short' },
      })
    }
    if (password.length > max) {
      return new InvalidPasswordError({
        message: 'password is too long',
        info: { code: 'too_long' },
      })
    }
    const passwordLengthError = _validatePasswordNotTooLong(password)
    if (passwordLengthError) {
      return passwordLengthError
    }
    if (
      !allowAnyChars &&
      !AuthenticationManager._passwordCharactersAreValid(password)
    ) {
      return new InvalidPasswordError({
        message: 'password contains an invalid character',
        info: { code: 'invalid_character' },
      })
    }
    if (typeof email === 'string' && email !== '') {
      const startOfEmail = email.split('@')[0]
      if (
        password.includes(email) ||
        password.includes(startOfEmail) ||
        email.includes(password)
      ) {
        return new InvalidPasswordError({
          message: 'password contains part of email address',
          info: { code: 'contains_email' },
        })
      }
      try {
        const passwordTooSimilarError =
          AuthenticationManager._validatePasswordNotTooSimilar(password, email)
        if (passwordTooSimilarError) {
          Metrics.inc('password-too-similar-to-email')
          return new InvalidPasswordError({
            message: 'password is too similar to email address',
            info: { code: 'too_similar' },
          })
        }
      } catch (error) {
        logger.error(
          { error },
          'error while checking password similarity to email'
        )
      }
      // TODO: remove this check once the password-too-similar checks are active?
    }
    return null
  },

  async setUserPassword(user, password) {
    return await AuthenticationManager.setUserPasswordInV2(user, password)
  },

  async checkRounds(user, hashedPassword, password) {
    // Temporarily disable this function, TODO: re-enable this
    if (Settings.security.disableBcryptRoundsUpgrades) {
      Metrics.inc('bcrypt_check_rounds', 1, { status: 'disabled' })
      return
    }
    // check current number of rounds and rehash if necessary
    const currentRounds = bcrypt.getRounds(hashedPassword)
    if (currentRounds < BCRYPT_ROUNDS) {
      Metrics.inc('bcrypt_check_rounds', 1, { status: 'upgrade' })
      return await AuthenticationManager._setUserPasswordInMongo(user, password)
    } else {
      Metrics.inc('bcrypt_check_rounds', 1, { status: 'success' })
    }
  },

  async hashPassword(password) {
    // Double-check the size to avoid truncating in bcrypt.
    const error = _validatePasswordNotTooLong(password)
    if (error) {
      throw error
    }

    const salt = await bcrypt.genSalt(BCRYPT_ROUNDS, BCRYPT_MINOR_VERSION)

    Metrics.inc('bcrypt', 1, {
      method: 'hash',
      path: BCRYPT_ROUNDS,
    })
    return await bcrypt.hash(password, salt)
  },

  async setUserPasswordInV2(user, password) {
    if (!user || !user.email || !user._id) {
      throw new Error('invalid user object')
    }
    const validationError = this.validatePassword(password, user.email)
    if (validationError) {
      throw validationError
    }
    // check if we can log in with this password. In which case we should reject it,
    // because it is the same as the existing password.
    const { match } = await AuthenticationManager._checkUserPassword(
      { _id: user._id },
      password
    )

    if (match) {
      throw new PasswordMustBeDifferentError()
    }

    let isPasswordReused
    try {
      isPasswordReused =
        await HaveIBeenPwned.promises.checkPasswordForReuse(password)
    } catch (error) {
      logger.err({ error }, 'cannot check password for re-use')
    }

    if (isPasswordReused) {
      throw new PasswordReusedError()
    }

    // password is strong enough or the validation with the service did not happen
    return await this._setUserPasswordInMongo(user, password)
  },

  async _setUserPasswordInMongo(user, password) {
    const hash = await this.hashPassword(password)
    const result = await db.users.updateOne(
      { _id: new ObjectId(user._id.toString()) },
      {
        $set: {
          hashedPassword: hash,
        },
        $unset: {
          password: true,
        },
      }
    )

    return _checkWriteResult(result)
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

  /**
   * Check if the password is similar to (parts of) the email address.
   * For now, this merely sends a metric when the password and
   * email address are deemed to be too similar to each other.
   * Later we will reject passwords that fail this check.
   *
   * This logic was borrowed from the django project:
   * https://github.com/django/django/blob/fa3afc5d86f1f040922cca2029d6a34301597a70/django/contrib/auth/password_validation.py#L159-L214
   */
  _validatePasswordNotTooSimilar(password, email) {
    password = password.toLowerCase()
    email = email.toLowerCase()
    const stringsToCheck = [email]
      .concat(email.split(/\W+/))
      .concat(email.split(/@/))
    for (const emailPart of stringsToCheck) {
      if (!_exceedsMaximumLengthRatio(password, MAX_SIMILARITY, emailPart)) {
        const similarity = DiffHelper.stringSimilarity(password, emailPart)
        if (similarity > MAX_SIMILARITY) {
          logger.warn(
            { email, emailPart, similarity, maxSimilarity: MAX_SIMILARITY },
            'Password too similar to email'
          )
          return new Error('password is too similar to email')
        }
      }
    }
  },

  getMessageForInvalidPasswordError(error, req) {
    const errorCode = error?.info?.code
    const message = {
      type: 'error',
    }
    switch (errorCode) {
      case 'not_set':
        message.key = 'password-not-set'
        message.text = req.i18n.translate('invalid_password_not_set')
        break
      case 'invalid_character':
        message.key = 'password-invalid-character'
        message.text = req.i18n.translate('invalid_password_invalid_character')
        break
      case 'contains_email':
        message.key = 'password-contains-email'
        message.text = req.i18n.translate('invalid_password_contains_email')
        break
      case 'too_similar':
        message.key = 'password-too-similar'
        message.text = req.i18n.translate('invalid_password_too_similar')
        break
      case 'too_short':
        message.key = 'password-too-short'
        message.text = req.i18n.translate('invalid_password_too_short', {
          minLength: Settings.passwordStrengthOptions?.length?.min || 8,
        })
        break
      case 'too_long':
        message.key = 'password-too-long'
        message.text = req.i18n.translate('invalid_password_too_long', {
          maxLength: Settings.passwordStrengthOptions?.length?.max || 72,
        })
        break
      default:
        logger.error({ err: error }, 'Unknown password validation error code')
        message.text = req.i18n.translate('invalid_password')
        break
    }
    return message
  },
}

module.exports = {
  _validatePasswordNotTooSimilar:
    AuthenticationManager._validatePasswordNotTooSimilar, // Private function exported for tests
  validateEmail: AuthenticationManager.validateEmail,
  validatePassword: AuthenticationManager.validatePassword,
  getMessageForInvalidPasswordError:
    AuthenticationManager.getMessageForInvalidPasswordError,
  authenticate: callbackifyMultiResult(AuthenticationManager.authenticate, [
    'user',
    'isPasswordReused',
  ]),
  createIfNotFoundAndLogin: AuthenticationManager.createIfNotFoundAndLogin,
  setUserPassword: callbackify(AuthenticationManager.setUserPassword),
  checkRounds: callbackify(AuthenticationManager.checkRounds),
  hashPassword: callbackify(AuthenticationManager.hashPassword),
  setUserPasswordInV2: callbackify(AuthenticationManager.setUserPasswordInV2),
  promises: AuthenticationManager,
}
