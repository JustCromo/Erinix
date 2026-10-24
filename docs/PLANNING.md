# Erinix: planning e scelte di progetto

Documento vivo. Spiega **cosa** abbiamo deciso e **perché**, in particolare per la sicurezza.
Il `README.md` spiegherà invece come installare e usare il tool.

Regola di lavoro: ogni nuova scelta di sicurezza o di architettura si aggiunge qui,
nella sezione giusta e nel registro finale.

Ultimo aggiornamento: 24 ottobre 2026.

---

## 1. Obiettivo e perimetro

Erinix è un IDS **host-based** per Linux, con risposta attiva opzionale. Non si limita
a registrare eventi singoli: ragiona per **catene d'attacco**, cioè sequenze di passi
collegati (servizio compromesso, shell, connessione verso l'esterno, privilege escalation),
come un attaccante che segue la strategia imparata nei pen test.

Priorità, in quest'ordine:

1. **Rilevamento**: la parte che deve funzionare meglio di tutte.
2. **Risposta**: poche azioni (terminare l'albero di processi, bloccare un IP), fatte con la massima prudenza.
3. **Assessment dell'incidente, console web, integrazione con Vulpnix**: costruiti sopra i primi due.

Fuori perimetro per ora: analisi del traffico di rete a livello di pacchetto (NIDS), anomaly detection statistica, multi-host.

## 2. La suite Nemirix

- **Nemirix**: la suite (il nome viene da *Nemi*, il bosco sacro in cui il *rex Nemorensis* vegliava senza mai abbassare la guardia, e dal suffisso gallico *-rix*, "re").
- **Vulpnix**: risk assessment, il *prima* dell'attacco (postura della macchina).
- **Erinix**: rilevamento, risposta e valutazione dell'incidente, il *durante* e il *dopo*.

Principi:

- **Ogni tool funziona da solo**, dal proprio terminale. La console web è il punto d'incontro e mostra i moduli installati.
- **Compartimentazione**: ogni tool ha il proprio utente di sistema e il proprio database, leggibile solo da quell'utente. Compromettere uno non dà accesso ai dati dell'altro.
- **Riconoscimento della suite**: una cartella di registro di proprietà di root, in cui ogni tool deposita la propria scheda (nome, versione, canale locale, chiave pubblica).
- **Contro chi finge di essere un tool**: comunicazione tramite socket Unix locali (il kernel dichiara l'utente dall'altra parte, dato non falsificabile) e report scambiati **firmati**; se la firma non torna il report è rifiutato.
- **Contratto dati comune**: schema JSON versionato di Vulpnix come base, stessa scala di gravità, stesse convenzioni.

## 3. Stack tecnico

| Scelta | Motivo |
|---|---|
| **Python** per agente e web | Padroneggiato dall'autore: in un progetto difeso a colloquio conta più della velocità teorica. Python è memory-safe. Il lavoro pesante lo fa il kernel (eBPF/auditd), non Python. |
| **FastAPI + SQLite** per console e DB | Architettura locale per la prima versione. Un file, zero configurazione. |
| **Regole in TOML** | Vedi sezione 6. Parser incluso in Python (`tomllib`), **zero dipendenze esterne**. |
| **Dipendenze minime e con versione fissata** | Ogni libreria in un processo root è superficie d'attacco. |

Agente e web sono **processi separati**: l'agente ha i privilegi, la web app **mai** root.

## 4. Sensori

**eBPF (CO-RE) è il sensore principale. auditd è il fallback. La modalità minimale è l'ultima rete di sicurezza.**

- **eBPF**: programmi nel kernel agganciati ai punti che interessano, eventi già strutturati, filtro a monte.
  Scelta **CO-RE** (compila una volta, gira ovunque) invece di bcc: nessun compilatore sulla macchina protetta,
  avvio istantaneo, è la pratica raccomandata oggi. Richiede kernel con BTF; compilazione per x86_64 e ARM.
- **auditd**: fallback su kernel vecchi o senza BTF.
- **Minimale**: `/proc` e log di autenticazione, a intervalli. Vede meno e in ritardo, ma non resta cieco.

Regole di funzionamento:

- All'avvio Erinix controlla privilegi, supporto eBPF/BTF e stato di auditd, sceglie la modalità e **dichiara sempre quale è e cosa non può vedere** (evento di stato del sensore, mostrato anche in console).
- Si può forzare a mano (`--sensor auditd`). Se la modalità forzata non è disponibile, Erinix **si rifiuta di partire** invece di degradare in silenzio.
- Cambio di modalità a caldo: il nuovo sensore parte **prima** che il vecchio si spenga, i doppioni vengono scartati, così non esiste un istante di cecità.
- **Anti-declassamento**: un attaccante potrebbe voler forzare il passaggio a un sensore che vede meno. Il cambio lo può chiedere solo root dal canale di controllo locale, e ogni cambio genera un alert.
- Il motore di correlazione **non sa da dove arrivano gli eventi**: riceve sempre lo stesso formato.
- La scelta della modalità sta in `sensors/selector.py` (rilevamento di privilegi, kernel, BTF, auditd) e si controlla con `erinix doctor`. Senza root il piano è «osservatore» e `doctor` dice anche cosa si potrebbe fare con i privilegi.

## 5. Privilegi

- **Modalità principale: root**, perché eBPF, auditd, blocco IP e terminazione processi lo richiedono.
- **Modalità rootless**: "osservatore che avvisa". Legge `/proc` e i log accessibili, apre esche su porte alte, invia alert. Non può usare eBPF/auditd né agire. Dichiara chiaramente i propri limiti all'avvio.
- Come servizio systemd: solo le capability necessarie, filesystem in sola lettura dove possibile.

## 6. Regole (`rules/*.toml`)

**Perché TOML e non YAML**: `tomllib` è nella libreria standard, quindi nessuna dipendenza esterna e meno superficie
d'attacco. Il parser YAML è storicamente fonte di vulnerabilità e `PyYAML` sarebbe un pacchetto in più dentro un processo privilegiato.
Il prezzo è una sintassi leggermente più verbosa per le catene.

Due tipi di regola:

- **`[[indicator]]`**: un evento singolo già sospetto.
- **`[[chain]]`** con `[[chain.step]]`: una sequenza di passi collegati (almeno 2).

Concetti:

- **`link`**: cosa rende i passi la stessa storia. `process_tree` (il processo del primo passo o un suo discendente), `login_session` (stessa sessione di login), `remote_ip` (stesso indirizzo remoto).
- **`window_seconds`**: entro quanto tempo devono avvenire i passi.
- **`count`**: il passo richiede N eventi (es. 5 login falliti).
- **`response`**: `report_only` (default), `interactive`, `auto`. Può essere sovrascritta per singolo passo, perché la risposta si aggancia al passo e non alla fine della catena (tempestività).
- **`mitre`**: tecniche MITRE ATT&CK collegate.

Sicurezza delle regole (verificata all'avvio da `erinix rules validate`):

1. **Solo dichiarative**: nessun codice, nessun `eval`.
2. **Nessuna espressione regolare**: solo valori esatti, prefissi e liste (elimina il ReDoS).
3. **Schema chiuso**: un campo sconosciuto invalida la regola. I campi ammessi in `match` dipendono dal tipo di evento.
4. **Regola malformata = regola scartata e segnalata**, mai eseguita; le altre restano attive.
5. **File fidati**: di root (o dell'utente che esegue Erinix), non scrivibili da gruppo/altri, non symlink, cartella inclusa. Se la cartella stessa è inaffidabile non si carica nulla.
6. **Limiti rigidi**: dimensione file, numero di regole, passi, elementi per lista, lunghezza stringhe.
7. **Percorsi sempre assoluti**, caratteri di controllo vietati.
8. **Una regola con risposta `auto` deve avere `justification`**: l'autore deve scrivere perché la certezza è assoluta. Rende l'automatismo revisionabile.
9. **Output sanificato**: tutto ciò che deriva da file esterni viene ripulito prima di essere stampato.

## 7. Modello degli eventi

Un formato comune per tutti i sensori, con una "busta" (id, orologio monotono per ordinare e orologio reale per mostrare, sorgente, processo, sessione di login) e un contenuto per famiglia: processo, rete, privilegi, file, autenticazione, **stato del sensore**.

Scelte di sicurezza:

1. **Identità del processo = PID + istante di avvio.** Il PID viene riciclato: un vecchio PID riassegnato non deve ereditare la catena di un altro processo.
2. **Mai fidarsi del nome del processo** (`comm`): un attaccante lo rinomina in `sshd` in un istante. Fa fede il percorso dell'eseguibile visto dal kernel. La discordanza è un segnale debole, da contestualizzare (è normale per script e interpreti).
3. **`loginuid`**: distingue una shell nata da un login (admin) da una nata da un servizio (probabile exploit).
4. **Tutto ciò che arriva dai processi è input ostile**: lunghezze limitate, byte non validi senza perdita né crash, numero di argomenti limitato.
5. **Dati conservati grezzi, escape solo in output** (proposta adottata, da riconfermare): le prove restano intatte e la dashboard non può diventare vettore d'attacco.
6. **Corsia riservata**: gli eventi critici (exec, cambi di uid, rete, stato sensore) viaggiano su un canale con spazio proprio.
7. **Albero dei processi a memoria limitata**: si sacrificano prima i processi terminati; se si perde un processo vivo lo si **conta e lo si dichiara**.
8. **Il sensore deve segnalare quando è cieco**: avvio, modalità, eventi persi, sensore fermato.
9. **Percorsi canonici dai sensori**: i percorsi dei file devono arrivare già risolti (niente `/etc/../etc/shadow`, niente symlink) e l'eseguibile deve essere quello visto dal kernel. Il motore confronta stringhe esatte e si fida del sensore su questo punto.

## 8. Correlazione e allarmi

- **Un solo alert per catena in corso**, che si aggiorna (stesso `alert_id`, `revision` crescente). Niente notifiche multiple per lo stesso attacco.
- **Gravità progressiva**: pari alla più alta tra i passi completati. Si segnala già dal primo passo, perché conta la tempestività.
- **La risposta si aggancia al passo**: per esempio "servizio che genera shell" seguito da "connessione esterna" è già una reverse shell confermata, e si interviene prima che l'attaccante cerchi la scalata. L'alert riporta il livello di risposta del passo appena raggiunto.

Come ragiona il motore (`engine/correlator.py`):

- **Un'istanza per "storia"**, identificata dal legame della regola: la radice dell'albero di processi (`process_tree`), la sessione di login (`login_session`) o l'indirizzo remoto (`remote_ip`).
- **I passi si completano in ordine.** Un solo evento completa al massimo un passo.
- **Finestra scorrevole per `count`** (come fail2ban): per un passo con `count = 5` valgono 5 eventi qualsiasi caduti negli ultimi `window_seconds`. Scelta per semplicità e prevedibilità; gli attacchi lenti si coprono con una seconda regola a finestra lunga e soglia più alta, non complicando il motore.
- **Dopo il primo passo** l'intera catena deve concludersi entro `window_seconds` dall'inizio; poi l'istanza scade e una nuova storia può ripartire.
- **Albero dei processi aggiornato dal motore**: un processo con lo stesso PID ma un altro istante di avvio è un altro processo e non eredita la catena.
- **Indicatori**: un alert per coppia (regola, processo); i duplicati vengono **contati** (`suppressed_duplicates`), non ignorati in silenzio.
- **Confronti senza regex**: valori esatti, prefissi, liste. Un campo sconosciuto non corrisponde mai (fallisce chiuso). Un eseguibile sconosciuto non conta come "inatteso" (il sensore potrebbe semplicemente non vederlo).

Memoria e sovraccarico del motore:

- **Limite di istanze per regola.** Al limite si sacrificano **solo** i candidati che non hanno completato nessun passo (i più vecchi per primi); le catene già avanzate non si toccano mai. Se non c'è nulla da sacrificare, il nuovo candidato viene rifiutato.
- **Ogni sacrificio o rifiuto è contato** e genera un alert critico `engine-overload` (al massimo uno al minuto): il flood è un segnale d'attacco, non un dettaglio tecnico.
- Il rinvio su disco degli eventi in eccesso spetta al bus a corsie (sezione 9), non al motore.

## 9. Resistenza al sovraccarico

Il sovraccarico è di per sé un segnale d'attacco: spesso il rumore serve a nascondere l'attacco vero. Impostazione per analogia col DDoS:

| Contro un DDoS | In Erinix |
|---|---|
| Limite per sorgente | Quota di eventi per albero di processi, utente o IP remoto |
| Filtrare vicino all'origine | Filtri eBPF dentro il kernel, prima di Python |
| Blocco temporaneo (blacklist con scadenza) | Terminazione dell'albero o blocco IP con scadenza |
| Distinguere legittimo da bot | Lista intoccabile e servizi noti |
| Corsie riservate (QoS) | Canale separato per gli eventi critici |
| Assorbire il picco | Buffer grandi e spill su disco |
| Monitorare e allertare | Raggiungere il limite è un allarme critico |

Principi:

- **Non si abbassa la guardia**: durante un flood la sensibilità sale, non scende.
- **Niente scarto silenzioso**: l'eccesso si rimanda (su disco), non si butta; se qualcosa va perso, lo si **conta e lo si dichiara**.
- **La risposta colpisce il punto più vicino all'origine** (il processo figlio, l'IP remoto), mai un servizio nella lista intoccabile: altrimenti l'attaccante userebbe Erinix per chiudere fuori l'amministratore.
- Limite onesto: con eBPF, se il buffer kernel-utente si riempie è il kernel a perdere eventi. Si riduce il rischio (buffer grande, filtri nel kernel) e si contano le perdite.

## 10. Risposta attiva

Livelli per regola: **auto** (poche catene a certezza assoluta, con giustificazione), **interattiva** (notifica e schermata dedicata con la catena completa), **solo segnalazione**.

Protezioni (valgono per **tutte** le azioni, `auto` compreso):

1. **Di default osserva e basta**: la risposta si attiva per scelta esplicita, mai al primo avvio. Una regola `auto` è inerte finché la risposta non è abilitata.
2. **Lista intoccabile**: PID 1, Erinix stesso, la sessione dell'amministratore e i suoi genitori, il suo IP, localhost, i servizi critici.
3. **Blocchi a scadenza**: se Erinix va in crash non resta nulla di permanente (si "fallisce aperto").
4. **Modalità prova** ("avrei bloccato X").
5. **Limite di azioni** nel tempo: troppe azioni sono più probabilmente un bug che un attacco.
6. **Interruttore generale** per spegnere ogni automatismo.
7. **Se l'utente non risponde non succede nulla**: nessuna azione "per scadenza".
8. **Conferme autenticate**: solo dalla console autenticata, altrimenti un attaccante userebbe Erinix contro l'utente.
9. **Nessun comando costruito con dati esterni**: gli IP sono validati e passati come argomenti, mai in stringhe di shell.
10. **Un solo punto di passaggio** (`guard.py`) tra regole e azioni: ogni azione futura eredita le protezioni.

## 11. Deception (honeyport)

Esche, non "falsi positivi": un utente legittimo non ha alcun motivo di toccare un servizio che non esiste, quindi chi lo fa è quasi certamente un attaccante.

- **Ibrido**: eBPF rileva la scansione; un piccolo processo di Erinix risponde sulle porte esca con banner finti. Simulare un servizio intero in eBPF sarebbe un incubo.
- **Le esche si mostrano solo all'IP che scansiona**, deviando le sue connessioni; gli utenti normali non vedono nulla.
- **Non si banna sulla sola scansione**: in una scansione SYN l'IP sorgente si può falsificare e si farebbero bannare IP innocenti. Si banna **solo dopo una connessione completata** e un'interazione con l'esca.
- **L'esca non diventa mai una porta d'ingresso**: banner, pochi byte letti, nessuna esecuzione, utente senza privilegi, processo isolato.
- **Vulpnix riconosce le esche** (tramite il registro della suite) e le esclude dal rischio reale.
- Da verificare prima delle gare: che le esche siano ammesse dal regolamento.

## 12. Assessment dell'incidente e integrazione con Vulpnix

Dopo la risposta Erinix valuta l'accaduto: **ricostruzione** (cronologia, punto d'ingresso, fin dove è arrivato l'attaccante), **esito della risposta**, **verifica di persistenza** (utenti, chiavi SSH, cron, servizi lasciati dall'attaccante: fermare la shell non basta) e **mitigazioni** collegate ai passi della catena.

Il cerchio con Vulpnix: Vulpnix indica dove guardare, Erinix vede e ferma, le mitigazioni dell'incidente diventano ciò che Vulpnix controlla alla scansione successiva. Il report di Vulpnix letto da Erinix è **input da validare e verificare nella firma**, non verità assoluta.

## 13. Interfaccia: console e comandi

Principio: l'agente (servizio con privilegi) non si avvia né si controlla dalla web app. Console e web sono due **client** della stessa API locale: chiudere uno dei due non spegne la protezione, e un client compromesso non ha i poteri dell'agente.

- **`erinix` apre una console interattiva** (prompt `erinix ▸`), come Vulpnix. Gli stessi comandi funzionano da riga di comando (`erinix doctor`), per systemd, script e test. Un unico registro di comandi alimenta entrambe.
- **Tabella chiusa di comandi**: ogni comando è una voce con funzione, aiuto e uso. Niente esecuzione in shell, niente comandi costruiti da testo esterno.
- **Zero dipendenze**: solo libreria standard (`readline` per cronologia e completamento).
- **Output sanificato**: ogni testo che arriva da file o processi passa da `safe()`, quindi nessuna sequenza di escape può essere iniettata nel terminale; le larghezze si calcolano sul testo semplice.
- **Cronologia** in `~/.local/state/erinix/history` con permessi 0600: non si legge se non è dell'utente o se è accessibile ad altri, non si scrive attraverso un symlink. I comandi marcati `sensitive` non finiscono in cronologia.
- **Colori**: informazioni ed evidenze in toni di riccio (marrone chiaro per le informazioni, marrone scuro per i bordi, arancio freddo per titoli e comandi); tutto il resto nel colore predefinito del terminale; rosso, verde e giallo riservati alle segnalazioni (gravità: `low` verde, `medium` giallo, `high` rosso, `critical` bianco su rosso). Supporto truecolor, 256 e 16 colori, oppure nessuno: si rispetta `NO_COLOR`, si può forzare con `ERINIX_COLOR=always|never` e disattivare per un comando con `--no-color`. Fallback ASCII se il terminale non è UTF-8.
- **Web locale** (da costruire): `erinix ui` apre la pagina; ascolto solo su `127.0.0.1`; accesso con link monouso rilasciato dal servizio dopo aver verificato chi lo chiede tramite il kernel (root o gruppo `erinix`); controllo dell'header `Host` contro il DNS rebinding; protezione CSRF; approvazioni di blocco solo da sessioni autenticate.

Comandi attuali: `help`, `version`, `doctor` (capacità della macchina e sensore previsto), `rules validate`, `rules list`, `replay` (attacchi simulati: `revshell`, `bruteforce`, `shadow`, `admin`).

Comandi previsti: `start`, `stop`, `status`, `ui`, `watch`, `alerts`, `incident`, `response` (status, dry-run, enable, panic), `block` (list, release), `sensor` (status, switch).

## 14. Console web e consegna

- Una **console unica di famiglia**, che mostra i moduli installati: solo Vulpnix, solo Erinix o entrambi (vista integrata).
- **DB separati** per tool. La console non tocca i DB: li interroga tramite il canale locale di ciascun tool, in sola lettura e con il minimo indispensabile.
- Esportazione dei report in HTML, Markdown e JSON.
- La web app è anche **il bersaglio del VSPT** (vulnerability scanning e pen test) richiesto dalla consegna: sicurezza fin dal progetto (argon2, query parametrizzate, CSRF, header di sicurezza, limite ai login, escape di tutto l'input dai tool), riferimento OWASP Top 10, poi scansioni, test manuali, report e secondo test di verifica. Il laboratorio richiede HTTPS e autenticazione sull'interfaccia raggiungibile.

## 15. Rischi residui (da dichiarare nel report)

- La **console** vede entrambi i tool: è l'unico punto in cui si incontrano. Si riduce (sola lettura, utente proprio, niente accesso ai file), non si elimina.
- Un attaccante che ottiene **root** può fermare Erinix: l'obiettivo è **accorgersene** (sensore fermato come allarme), non impedirlo.
- Con eBPF il kernel può perdere eventi se il buffer si riempie: si contano e si dichiarano.
- Ogni regola ha falsi positivi possibili; le regole `auto` sono poche, motivate e revisionabili.

## 16. Piano di lavoro e date

- **6 novembre 2026**: sfida red team vs blue team (Raspberry). Erinix "da gara": sensore, poche catene solide, esche, risposta con scadenza e lista intoccabile, alert da terminale, nessuna console. Erinix è costruito per **qualsiasi Linux**, non su misura del Raspberry.
- **19 novembre 2026**: consegna finale (tool di risk assessment e applicazione web, con VSPT). Console Nemirix, integrazione con Vulpnix, valutazione degli incidenti, report.

Ordine di sviluppo: modello eventi e albero dei processi (fatto), regole (fatto), motore di correlazione (fatto), console e comandi di base (fatto), guardia e risposta, bus a corsie, sensore eBPF, fallback auditd, esche, storage, console.

## 17. Registro delle decisioni

| Data | Decisione | Perché |
|---|---|---|
| 2026-10-24 | Python + FastAPI + SQLite | Linguaggio padroneggiato, tempi stretti |
| 2026-10-24 | eBPF principale, auditd fallback, minimale | Visibilità massima, nessuno resta senza protezione |
| 2026-10-24 | eBPF con CO-RE (non bcc) | Nessun compilatore sulla macchina protetta, pratica moderna |
| 2026-10-24 | Root come modalità principale, rootless come osservatore | Servono i privilegi per sensori e risposta |
| 2026-10-24 | Risposta ibrida (auto solo a certezza assoluta, interattiva altrove) | Equilibrio tra tempestività ed errori |
| 2026-10-24 | Nessun scarto silenzioso sotto flood; corsia riservata | "Non abbassare la guardia" |
| 2026-10-24 | DB e utenti separati per tool; registro e firma della suite | Compartimentazione |
| 2026-10-24 | Console unica che si adatta ai tool installati | Un solo bersaglio da mettere in sicurezza |
| 2026-10-24 | Honeyport con ban solo dopo connessione completa | Lo spoofing dell'IP in scansione SYN farebbe bannare innocenti |
| 2026-10-24 | Regole in **TOML**, zero dipendenze, nessuna regex, `auto` con giustificazione | Meno superficie d'attacco, niente ReDoS, automatismi revisionabili |
| 2026-10-24 | Il file/cartella delle regole deve essere fidato (proprietario, permessi, no symlink) | Chi scrive le regole comanda il tool |
| 2026-10-24 | `count` con finestra scorrevole; attacchi lenti coperti da regole a finestra lunga | Semplice, prevedibile, già usato da fail2ban |
| 2026-10-24 | Motore: istanze limitate per regola, si sacrificano solo candidati non avanzati, con alert critico | Un flood non deve poter cancellare un attacco già in corso, né passare sotto silenzio |
| 2026-10-24 | Console interattiva e riga di comando dallo stesso registro; agente separato, CLI e web come client | Chiudere l'interfaccia non deve spegnere la protezione; un client compromesso non ha i poteri dell'agente |
| 2026-10-24 | Palette a toni di riccio per le informazioni, semaforo per le segnalazioni; `NO_COLOR` rispettato | Leggibilità e identità visiva coerente con la suite |

### Ancora da decidere o riconfermare

- Scala di gravità condivisa con Vulpnix (qui: `low`, `medium`, `high`, `critical`; va allineata allo schema di Vulpnix).
- Dati ostili: grezzi nel DB con escape in output (proposta adottata).
- Strato di caricamento eBPF da Python (libreria esistente o piccolo componente in C).
- Regolamento della sfida red vs blue (esche, blocchi IP, disponibilità dei servizi).
- Convenzioni della console di Vulpnix (prompt, banner, comandi, colori) da confrontare con quelle di Erinix, per una famiglia coerente.
