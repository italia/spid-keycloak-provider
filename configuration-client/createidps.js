const { from, of, concat } = require('rxjs')
const { map, mergeMap } = require('rxjs/operators')

const { config, patchTemplateWithRealm } = require('./src/common')
const { httpGrabIdPsMetadata, httpCallKeycloakImportConfig, httpCallKeycloakCreateIdP, httpCallKeycloakDeleteIdP, httpCallKeycloakCreateAllMappers } = require('./src/http')


const idPTemplate = JSON.parse(patchTemplateWithRealm('./template/idpmodel.json'))


//recupero url metadati
var getOfficialSpididPsMetadata$ = from(httpGrabIdPsMetadata())
    .pipe(mergeMap(httpResponse => from(httpResponse.data.data)))

if (config.createSpidTestIdP === 'true') {
    let spidTestIdPOfficialMetadata = {
        ipa_entity_code: config.spidTestIdPAlias,
        entity_id: config.spidTestIdPAlias,
        entity_name: config.spidTestIdPAlias,
        metadata_url: config.spidTestIdPMetadataURL,
        entity_type: 'IdP'
    }

    getOfficialSpididPsMetadata$ = concat(getOfficialSpididPsMetadata$, of(spidTestIdPOfficialMetadata))

}



//richiesta cancellazione degli idPs da keycloak
var deleteKeycloakSpidIdPs$ = getOfficialSpididPsMetadata$
    .pipe(mergeMap(spidIdPOfficialMetadata => from(httpCallKeycloakDeleteIdP(spidIdPOfficialMetadata.entity_name).then(httpResponse => spidIdPOfficialMetadata))))


//richiesta conversione in import-config model [idP,import-config-response]
var getKeycloakImportConfigModels$ = deleteKeycloakSpidIdPs$
    .pipe(mergeMap(spidIdPOfficialMetadata => from(httpCallKeycloakImportConfig(spidIdPOfficialMetadata.metadata_url).then(httpResponse => [spidIdPOfficialMetadata, httpResponse.data]))))

//trasformazione ed arricchimento => modello per creare l'idP su keycloak
var enrichedModels$ = getKeycloakImportConfigModels$
    .pipe(map(spidIdPOfficialMetadataWithImportConfigModel => {
        let [idPOfficialMetadata, importConfigModel] = spidIdPOfficialMetadataWithImportConfigModel
        let config = { ...idPTemplate.config, ...importConfigModel }
        let firstLevel = {
            alias: idPOfficialMetadata.entity_name
        }
        let merged = { ...idPTemplate, ...firstLevel }
        merged.config = config
        return merged
    }))

//creazione dello spid idP su keycloak
var createSpidIdPsOnKeycloak$ = enrichedModels$
    .pipe(mergeMap(idPToCreateModel => from(httpCallKeycloakCreateIdP(idPToCreateModel).then(httpResponse => [idPToCreateModel.alias, httpResponse]))))

//creazione dei mappers per lo spid id
var createKeycloackSpidIdPsMappers$ = createSpidIdPsOnKeycloak$.pipe(mergeMap(idPAliasWithHttpCreateResponse => {
    let [alias, createResponse] = idPAliasWithHttpCreateResponse
    return from(httpCallKeycloakCreateAllMappers(alias).then(response => { return { alias, create_response: createResponse, mapper_response: response } }))
}))


createKeycloackSpidIdPsMappers$.subscribe(console.log)

//httpCallKeycloakImportRealm().then(() => createKeycloackSpidIdPsMappers$.subscribe(console.log))
