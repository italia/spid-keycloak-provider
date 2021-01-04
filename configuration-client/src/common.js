require('dotenv').config()
const fs = require('fs')

const config = {
    ...process.env
}

exports.config = config

exports.usernameMapperTemplate = require('../template/username_mm.json')
exports.lastnameMapperTemplate = require('../template/lastname_mm.json')
exports.firstnameMapperTemplate = require('../template/firstname_mm.json')
exports.emailMapperTemplate = require('../template/email_mm.json');


exports.patchTemplateWithRealm = function (templateFilePath) {
    return fs.readFileSync(templateFilePath).toString().replace(/%CHANGEIT%/g, config.realm)
}

