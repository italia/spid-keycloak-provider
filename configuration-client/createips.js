const { from, of, concat } = require('rxjs')
const { map, mergeMap } = require('rxjs/operators')

const { config, patchTemplateWithRealm } = require('./src/common')
const { httpGrabIpsMetadata, httpCallKeycloakImportConfig, httpCallKeycloakCreateIp, httpCallKeycloakDeleteIp, httpCallKeycloakCreateAllMappers } = require('./src/http')


const ipTemplate = JSON.parse(patchTemplateWithRealm('./template/ipmodel.json'))


//recupero url metadati
var getOfficialSpidipsMetadata$ = from(httpGrabIpsMetadata())
    .pipe(mergeMap(httpResponse => from(httpResponse.data.data)))

if (config.createSpidTestIp) {
    let spidTestIpOfficialMetadata = {
        ipa_entity_code: config.spidTestIpAlias,
        entity_id: config.spidTestIpAlias,
        entity_name: config.spidTestIpAlias,
        metadata_url: config.spidTestIpMetadataURL,
        entity_type: 'IdP'
    }

    getOfficialSpidipsMetadata$ = concat(getOfficialSpidipsMetadata$, of(spidTestIpOfficialMetadata))

}



//richiesta cancellazione degli ips da keycloak   
var deleteKeycloakSpidIps$ = getOfficialSpidipsMetadata$
    .pipe(mergeMap(spidIpOfficialMetadata => from(httpCallKeycloakDeleteIp(spidIpOfficialMetadata.entity_name).then(httpResponse => spidIpOfficialMetadata))))


//richiesta conversione in import-config model [ip,import-config-response]
var getKeycloakImportConfigModels$ = deleteKeycloakSpidIps$
    .pipe(mergeMap(spidIpOfficialMetadata => from(httpCallKeycloakImportConfig(spidIpOfficialMetadata.metadata_url).then(httpResponse => [spidIpOfficialMetadata, httpResponse.data]))))

//trasformazione ed arricchimento => modello per creare l'ip su keycloak
var enrichedModels$ = getKeycloakImportConfigModels$
    .pipe(map(spidIpOfficialMetadataWithImportConfigModel => {
        let [ipOfficialMetadata, importConfigModel] = spidIpOfficialMetadataWithImportConfigModel
        let config = { ...ipTemplate.config, ...importConfigModel }
        let firstLevel = {
            alias: ipOfficialMetadata.entity_name
        }
        let merged = { ...ipTemplate, ...firstLevel }
        merged.config = config
        return merged
    }))

//creazione dello spid ip su keycloak    
var createSpidIpsOnKeycloak$ = enrichedModels$
    .pipe(mergeMap(ipToCreateModel => from(httpCallKeycloakCreateIp(ipToCreateModel).then(httpResponse => [ipToCreateModel.alias, httpResponse]))))

//creazione dei mappers per lo spid id
var createKeycloackSpidIpsMappers$ = createSpidIpsOnKeycloak$.pipe(mergeMap(ipAliasWithHttpCreateResponse => {
    let [alias, createResponse] = ipAliasWithHttpCreateResponse
    return from(httpCallKeycloakCreateAllMappers(alias).then(response => { return { alias, create_response: createResponse, mapper_response: response } }))
}))


createKeycloackSpidIpsMappers$.subscribe(console.log)

//httpCallKeycloakImportRealm().then(() => createKeycloackSpidIpsMappers$.subscribe(console.log))
