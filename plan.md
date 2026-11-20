# Piano di sviluppo: prima SSO, poi RBAC

## Obiettivo e perimetro

Due milestone rilasciabili separatamente, suddivise in PR incrementali:

1. **SSO Keycloak:** login, provisioning utenti, sessioni, logout e accesso locale di emergenza.
2. **RBAC:** gruppi Keycloak mappati a ruoli per workspace/progetto, autorizzazione backend e controllo delle pagine.

Requisiti concordati:

- Login ordinario integrato con Keycloak.
- Gruppi Keycloak mappati a Viewer, Developer e Admin.
- Ruoli distinti per workspace e progetto.
- Autorizzazione su pagine, dati e creazione di oggetti.
- Il ruolo limita anche il proprietario degli oggetti.
- Account locale esclusivamente per emergenza.

**Durante la prima milestone non cambiano ancora le regole di autorizzazione esistenti.** Un login Keycloak riuscito non implica che Viewer, Developer e Admin siano gia applicati: questo diventa operativo soltanto con la seconda milestone.

Il piano riutilizza gli schemi `SSOConfig` e `SSOUserProfile`, il servizio di autenticazione, le tabelle `authz_*` e le guardie gia presenti. Non prevede modifiche al motore di esecuzione dei grafi salvo gli adattamenti necessari a propagare correttamente l'identita.

L'analisi riguarda il codice presente nel repository; eventuali plugin installati nell'ambiente di deployment devono essere verificati prima dell'implementazione.

## Milestone 1 - SSO integrato con Keycloak

### SSO-01 - Definire il contratto di autenticazione e configurare Keycloak

**Obiettivo:** stabilire un solo percorso di login ordinario e predisporre un ambiente riproducibile.

**Attivita**

- Configurare un realm e un client OIDC dedicati a Langflow.
- Usare **Authorization Code Flow con PKCE S256**, con scambio del codice nel backend.
- Configurare redirect URI e URL di logout esatti, evitando wildcard in produzione.
- Configurare audience e claim necessari: identita, nome visualizzato e gruppi.
- Disabilitare password grant e implicit flow per questo client.
- Definire durata della sessione, refresh, timeout di inattivita e comportamento quando Keycloak non e disponibile.
- Definire il contratto dell'account locale di emergenza.
- Preparare configurazioni distinte per sviluppo, staging e produzione, senza segreti nel repository.

**Decisione architetturale proposta**

```text
Browser -> Backend Langflow -> Keycloak
                  |
                  v
        Sessione applicativa Langflow
```

Il browser non conserva refresh token Keycloak in `localStorage`. Il backend mantiene le informazioni necessarie alla sessione federata, adattandosi al contratto di autenticazione gia usato dal frontend.

**Risultato:** configurazione Keycloak riproducibile e contratto dei flussi login, refresh e logout approvato.

### SSO-02 - Implementare il modulo OIDC e il ciclo login/callback

**Dipende da:** SSO-01.

**Superfici principali**

- `src/backend/base/langflow/services/auth/`
- `src/backend/base/langflow/plugin_routes.py`
- `src/backend/base/langflow/services/database/models/auth/sso.py`

**Attivita**

- Implementare l'integrazione tramite i punti di estensione esistenti, evitando un secondo sistema di autenticazione parallelo.
- Riutilizzare `SSOConfig` per configurazione del provider e gestione cifrata del client secret.
- Aggiungere endpoint di avvio login, callback e discovery pubblica minima del provider. I percorsi saranno definiti nella specifica API.
- Usare una libreria OIDC consolidata per il protocollo; riutilizzare gli helper esistenti dove compatibili.
- Conservare `state`, `nonce` e verificatore PKCE in uno storage condiviso o persistente, con scadenza e consumo singolo.
- Validare firma, issuer, audience, scadenze e nonce secondo il tipo di token.
- Consentire il ritorno soltanto a percorsi applicativi autorizzati.
- Gestire annullamento del login, callback scaduto, callback ripetuto e indisponibilita del provider.

**Criterio di completamento:** login funzionante anche quando avvio e callback vengono gestiti da worker diversi; callback non validi non producono una sessione.

### SSO-03 - Collegare identita Keycloak e utenti Langflow

**Dipende da:** SSO-02.

**Superfici principali**

- `src/backend/base/langflow/services/auth/service.py`
- `src/backend/base/langflow/services/database/models/auth/sso.py`
- Inizializzazione degli utenti e dei progetti personali.

**Attivita**

- Riutilizzare `SSOUserProfile` e il provisioning gia presente.
- Associare l'identita tramite connessione/provider stabile e `sub`, vincolando la connessione all'issuer.
- Aggiornare soltanto gli attributi del profilo previsti, senza trasformarli in privilegi.
- Impedire la creazione di utenti duplicati durante login concorrenti.
- Non collegare automaticamente account preesistenti sulla sola base dell'email.
- Definire una procedura amministrativa per collegare account locali esistenti e preservarne flow e proprieta.
- Bloccare login e refresh per utenti disattivati.
- Impedire l'uso di password locali e dei relativi reset per utenti gestiti da SSO.
- Acquisire i gruppi verificati per il futuro RBAC, **senza assegnare automaticamente privilegi amministrativi in questa fase**.

**Criterio di completamento:** accessi ripetuti risolvono lo stesso utente; nessun account SSO diventa superuser per effetto del provisioning.

### SSO-04 - Integrare sessioni, refresh, logout e revoca

**Dipende da:** SSO-03.

**E la parte piu delicata della milestone SSO.** Il login non deve creare una sessione Langflow che possa essere rinnovata indefinitamente dopo la revoca in Keycloak.

**Attivita**

- Collegare la sessione applicativa a provider, utente e identificatore di sessione Keycloak.
- Valutare lo storage esistente e aggiungere tramite Alembic solo i dati mancanti: scadenze, stato di revoca e credenziali federate strettamente necessarie.
- Cifrare a riposo i token che devono essere conservati.
- Integrare il refresh con gli endpoint e gli hook frontend esistenti.
- Serializzare il refresh concorrente tra schede e worker, gestendo la rotazione dei refresh token.
- Usare cookie `HttpOnly`, `Secure` e una policy `SameSite` coerente con il callback OIDC; proteggere le operazioni basate su cookie dal CSRF.
- Implementare logout locale e logout federato.
- Implementare il back-channel logout Keycloak, validandone il messaggio e revocando le sessioni correlate.
- Definire il comportamento in caso di errore del provider: nessuna estensione non autorizzata della sessione e nessun fallback automatico all'auto-login.
- Esplicitare la finestra residua di validita degli access token: la verifica offline della firma non garantisce revoca immediata.

**Criterio di completamento:** refresh, scadenza e logout funzionano su piu worker; una sessione revocata non puo essere rigenerata dal percorso di refresh locale.

### SSO-05 - Integrare il frontend e l'accesso di emergenza

**Dipende da:** SSO-02, SSO-03 e SSO-04.

**Superfici principali**

- `src/frontend/src/customization/components/custom-login-sso-options.tsx`
- Pagina di login.
- `src/frontend/src/components/authorization/authGuard/`
- Hook API di autenticazione e store auth.

**Attivita**

- Aggiungere il login Keycloak e gli stati di errore/annullamento.
- Ripristinare il percorso richiesto prima del login, senza redirect arbitrari.
- Allineare inizializzazione dell'app, rilevamento della sessione e refresh.
- Evitare loop di redirect e richieste di refresh ripetute su sessioni definitivamente scadute.
- Rendere il login locale utilizzabile solo dagli account esplicitamente autorizzati per emergenza, con enforcement backend.
- Proteggere l'accesso di emergenza con controlli operativi appropriati: credenziali custodite, limitazione dei tentativi, eventuale restrizione di rete e audit.
- Tradurre tutte le nuove stringhe attraverso i18n.

**Criterio di completamento:** un utente ordinario usa soltanto Keycloak; l'account di emergenza resta utilizzabile durante un guasto del provider senza rendere disponibile un bypass agli altri utenti.

### SSO-06 - Consolidamento e rilascio SSO

**Dipende da:** tutte le PR SSO precedenti.

**Verifiche previste**

- Primo login, login successivo e login concorrenti.
- Utente disabilitato e identita con email uguale a un account locale.
- Token scaduti, issuer/audience errati e rotazione delle chiavi.
- Callback ripetuto, `state` errato e redirect non consentito.
- Refresh concorrente, logout locale/federato e revoca.
- Funzionamento con piu worker.
- Compatibilita dei percorsi SSE/WebSocket e politica esplicita per API key e integrazioni.

**Rilascio**

- Migrare e collegare gli utenti esistenti in staging.
- Attivare SSO per un gruppo pilota.
- Documentare configurazione, recupero dell'accesso e rollback.
- Esplicitare che **il sistema conserva ancora le autorizzazioni precedenti** finche RBAC non viene attivato.

**Gate milestone:** nessuna implementazione RBAC viene considerata un prerequisito per completare il login SSO.

## Milestone 2 - RBAC per workspace, progetto, pagine e oggetti

### RBAC-01 - Formalizzare la matrice dei permessi

**Dipende da:** milestone SSO completata.

**Attivita**

- Censire risorse e operazioni: flow/componenti salvati, progetti, file, knowledge base, variabili, connessioni, deployment e funzioni amministrative.
- Separare le tre dimensioni della tabella seguente.
- Definire Viewer, Developer e Admin per ciascuna risorsa.
- Trattare separatamente `create`, `write`, `delete`, `execute`, `deploy` e gestione dei segreti.
- Formalizzare precedenza tra ruoli globali, workspace e progetto.
- Definire come combinare piu gruppi nello stesso ambito.
- Stabilire il rapporto tra ruoli e condivisioni: **una condivisione o la proprieta non deve superare il limite del ruolo**.
- Distinguere Admin di ambito, Admin globale e account di emergenza.

| Dimensione | Domanda |
|---|---|
| Pagina | Posso accedere a questa sezione? |
| Ambito | Posso creare questo tipo di oggetto nel progetto X? |
| Oggetto | Posso leggere, modificare o eseguire questo oggetto? |

**Proposta da approvare prima del codice:** ruolo ereditato dal workspace, sostituito dall'eventuale ruolo esplicito sul progetto. Nessun ruolo applicabile comporta diniego.

**Risultato:** matrice e casi di esempio utilizzabili come specifica dei test, senza decisioni implicite nel codice.

### RBAC-02 - Completare il modello workspace/progetto

**Dipende da:** RBAC-01.

**Attivita**

- Verificare eventuali implementazioni downstream gia disponibili.
- Completare nel core il registro dei workspace e l'associazione autorevole dei progetti.
- Definire quali risorse rimangano personali/globali e quali appartengano a un progetto.
- Estendere modelli e API soltanto dove necessario.
- Migrare gli oggetti esistenti verso ambiti deterministici.
- Gestire esplicitamente il progetto personale creato al provisioning: la sua esistenza non attribuisce un permesso di creazione al Viewer.
- Definire autorizzazione e aggiornamento dei permessi in caso di spostamento tra progetti/workspace.

**Criterio di completamento:** ogni risorsa protetta ha un ambito risolvibile dal backend; un ID inviato dal client non puo cambiare arbitrariamente tale ambito.

### RBAC-03 - Implementare il servizio di autorizzazione

**Dipende da:** RBAC-01 e RBAC-02.

**Superfici principali**

- `lfx.services.authorization.BaseAuthorizationService`
- `src/backend/base/langflow/services/authorization/service.py`
- Tabelle `authz_*` e `casbin_rule`.
- Registrazione tramite `lfx.toml`.

**Attivita**

- Implementare l'enforcer, preferibilmente Casbin, con diniego predefinito.
- Usare le tabelle amministrative come fonte canonica e le policy compilate come dati derivati.
- Implementare decisioni singole, batch, permessi effettivi e filtri di visibilita.
- Gestire ereditarieta e precedenze secondo RBAC-01.
- Coordinare aggiornamento delle policy e invalidazione delle cache tra worker.
- Rendere esplicita la modalita rigorosa, preservando il comportamento OSS solo quando tale modalita non e attiva.
- Impedire l'avvio operativo in modalita rigorosa se manca il servizio di enforcement.

**Criterio di completamento:** lo stesso utente puo essere Developer nel progetto A e Viewer nel B, con decisioni coerenti anche dopo aggiornamenti concorrenti.

### RBAC-04 - Mappare i gruppi Keycloak e gestire le revoche

**Dipende da:** RBAC-03 e milestone SSO.

**Attivita**

- Introdurre una configurazione amministrata del mapping descritto sotto.
- Riutilizzare `AuthzRoleAssignmentGrant` per registrare la provenienza.
- Riconciliare i gruppi al login e al rinnovo/verifica della sessione, non soltanto nelle richieste bearer esterne.
- Rimuovere le assegnazioni IdP revocate senza cancellare eventuali altre fonti legittime.
- Non interpretare claim incompleti come una lista autorevole vuota.
- Definire una strategia restrittiva quando non e possibile confermare assegnazioni scadute.
- Registrare modifiche e revoche senza salvare token o claim sensibili nei log.
- Definire chi puo modificare il mapping: un Admin di progetto non deve poter attribuirsi un ruolo globale.

```text
Provider + gruppo Keycloak -> ruolo -> ambito
```

**Criterio di completamento:** le modifiche ai gruppi si riflettono nei permessi entro una finestra misurabile e documentata.

### RBAC-05 - Allineare tutte le guardie e i percorsi di creazione

**Dipende da:** RBAC-03 e RBAC-04.

**Superfici principali**

- `src/backend/base/langflow/services/authorization/guards.py`
- `src/backend/base/langflow/services/authorization/listing.py`
- `src/backend/base/langflow/api/v1/authz_me.py`
- API delle risorse.

**Attivita**

- Disabilitare il bypass del proprietario nella modalita rigorosa.
- Applicare la stessa regola a liste, dettagli e permessi restituiti al frontend.
- Verificare `create` sul contenitore effettivo prima dell'inserimento.
- Coprire creazione diretta, importazione, duplicazione, fork, template, ZIP e operazioni batch.
- Verificare i controlli su spostamenti e copie tra ambiti.
- Filtrare le query prima della paginazione, evitando conteggi o metadati di risorse non visibili.
- Coprire API key, MCP, percorsi agentici e job pertinenti.
- Rendere coerenti risposte 403/404 e audit.

**Criterio di completamento centrale:** **un Viewer proprietario non puo creare o modificare, nemmeno chiamando direttamente le API.**

### RBAC-06 - Integrare capability, pagine e controlli frontend

**Dipende da:** RBAC-03 e dal contratto di RBAC-01; completamento dopo RBAC-05.

**Superfici principali**

- `src/frontend/src/routes.tsx`
- `src/frontend/src/contexts/permissionsContext.tsx`
- `src/frontend/src/utils/permissionUtils.ts`
- Hook delle permission e componenti di navigazione/creazione.

**Attivita**

- Estendere il contratto backend per capability di pagina e creazione, senza richiedere l'ID di un oggetto ancora inesistente.
- Aggiungere guardie alle route, inclusi accessi tramite URL diretto.
- Filtrare menu e sezioni.
- Disabilitare/nascondere azioni secondo una convenzione UX uniforme.
- Gestire caricamento ed errori senza abilitare implicitamente le azioni.
- Invalidare i permessi quando cambiano utente, ambito o policy.
- Mostrare il ruolo effettivo e l'ambito corrente.
- Aggiungere la gestione amministrativa minima del mapping e una vista delle assegnazioni sincronizzate.
- Localizzare messaggi e stati UI.

**Criterio di completamento:** la UI riflette le decisioni backend, senza implementare una seconda matrice dei ruoli in React.

### RBAC-07 - Migrazione e attivazione progressiva

**Dipende da:** tutte le PR RBAC precedenti.

**Attivita**

- Assegnare gli ambiti e i ruoli iniziali agli utenti esistenti.
- Preparare scenari reali con piu utenti, workspace, progetti e gruppi.
- Verificare soprattutto dinieghi, revoche e confini tra ambiti.
- Introdurre, se necessaria, una modalita di valutazione delle nuove policy senza bloccare le richieste.
- Attivare RBAC su un ambiente pilota dopo aver verificato i permessi amministrativi.
- Monitorare errori, dinieghi anomali, ritardi di sincronizzazione e cache.
- Predisporre un rollback controllato: non deve equivalere a rendere accessibile a tutti cio che prima era protetto.

**Gate milestone:** pagine, API, liste e percorsi alternativi applicano la stessa policy; proprieta e API key non consentono di aggirarla.

## Sequenza delle consegne

```text
SSO-01 -> SSO-02 -> SSO-03 -> SSO-04 -> SSO-05 -> SSO-06
                                                  |
                                        SSO rilasciato
                                                  |
                                                  v
RBAC-01 -> RBAC-02 -> RBAC-03 -> RBAC-04 -> RBAC-05 -> RBAC-06 -> RBAC-07
```

Il risultato e una sequenza di **13 PR funzionali**, eventualmente suddivise ulteriormente quando servono migrazioni indipendenti.

Le tre condizioni da non posticipare sono:

- **Sessioni SSO realmente revocabili.**
- **Ambiti risolti dal backend.**
- **Rimozione coerente del bypass del proprietario in modalita RBAC rigorosa.**
