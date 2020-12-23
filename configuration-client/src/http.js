const { config } = require('./common')
const qs = require('qs')
const axios = require('axios')
const { usernameMapperTemplate, lastnameMapperTemplate, firstnameMapperTemplate, emailMapperTemplate, patchTemplateWithRealm } = require('./common')


const tokenConfig = {
    method: 'post',
    url: config.keycloakServerBaseURL + '/auth/realms/' + config.adminRealm + '/protocol/openid-connect/token',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    data: qs.stringify({
        'client_id': config.adminClientId,
        'username': config.adminUsername,
        'password': config.adminPwd,
        'grant_type': 'password'
    })
};


exports.httpGrabIpsMetadata = function () {
    return axios({
        method: 'get',
        url: config.spidMetadataOfficialURL,
        headers: {}
    })
        .catch(function (error) {
            console.log(error);
        });
}

const httpGrabKeycloaktoken = function () {
    return axios(tokenConfig)
        .then(response => response.data.access_token)
        .catch(function (error) {
            console.log(error);
        });
}

exports.httpGrabKeycloaktoken = httpGrabKeycloaktoken

exports.httpCallKeycloakImportConfig = function (ipsMetadataUrl) {
    return httpGrabKeycloaktoken().then(token => {
        let data = JSON.stringify({ "providerId": "spid", "fromUrl": ipsMetadataUrl });
        let axiosConfig = {
            method: 'post',
            url: config.keycloakServerBaseURL + '/auth/admin/realms/' + config.realm + '/identity-provider/import-config',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            data: data
        };
        return axios(axiosConfig)
            .catch(function (error) {
                console.log(error);
            });
    })

}



exports.httpCallKeycloakCreateIp = function (ipModel) {
    return httpGrabKeycloaktoken().then(token => {
        let data = JSON.stringify(ipModel);
        let axiosConfig = {
            method: 'post',
            url: config.keycloakServerBaseURL + '/auth/admin/realms/' + config.realm + '/identity-provider/instances',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            data: data
        };
        return axios(axiosConfig)
            .catch(function (error) {
                console.log(error);
            });
    })
}


exports.httpCallKeycloakDeleteIp = function (ipAlias) {
    return httpGrabKeycloaktoken().then(token => {
        let axiosConfig = {
            method: 'delete',
            url: config.keycloakServerBaseURL + '/auth/admin/realms/' + config.realm + '/identity-provider/instances/' + ipAlias,
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        };
        return axios(axiosConfig)
            .catch(function (error) {
                console.log(error);
            });
    })
}

const httpCallKeycloakCreateMapper = function (ipAlias, mapperModel) {
    return httpGrabKeycloaktoken().then(token => {
        mapperModel.identityProviderAlias = ipAlias
        let data = JSON.stringify(mapperModel);
        let axiosConfig = {
            method: 'post',
            url: config.keycloakServerBaseURL + '/auth/admin/realms/' + config.realm + '/identity-provider/instances/' + ipAlias + '/mappers',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            data: data
        };
        return axios(axiosConfig)
            .catch(function (error) {
                console.log(error);
            });
    })
}

exports.httpCallKeycloakCreateAllMappers = function (ipAlias) {
    return Promise.all([
        httpCallKeycloakCreateMapper(ipAlias, usernameMapperTemplate),
        httpCallKeycloakCreateMapper(ipAlias, lastnameMapperTemplate),
        httpCallKeycloakCreateMapper(ipAlias, firstnameMapperTemplate),
        httpCallKeycloakCreateMapper(ipAlias, emailMapperTemplate)
    ])
}

exports.httpCallKeycloakImportRealm = function () {
    return httpGrabKeycloaktoken().then(token => {
        let data = patchTemplateWithRealm('./template/realm-template.json');
        let axiosConfig = {
            method: 'post',
            url: config.keycloakServerBaseURL + '/auth/admin/realms/',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            data: data
        };
        return axios(axiosConfig)
            .catch(function (error) {
                console.log(error);
            });
    })
}