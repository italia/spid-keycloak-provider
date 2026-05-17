Directory contenente i certificati generati tramite lo script create-self-signed-certificates.sh ed il certificato
da importare nel truststore per la configurazione e la validazione del provider, come indicato nel README del
progetto.

Il file è stato copiato da questa directory: https://github.com/italia/spid-saml-check/tree/master/src/config-sample

Il certificato è montato nell'immagine docker del keycloak seguendo le specifiche indicate in questa pagina:
https://www.keycloak.org/server/keycloak-truststore#_configuring_the_system_truststore
