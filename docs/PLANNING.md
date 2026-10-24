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

## 8. Correlazione e allarmi

- **Un solo alert per catena in corso**, che si aggiorna. Niente notifiche multiple per lo stesso attacco.
- **Gravità progressiva**: cresce con i passi completati. Si segnala già dal primo passo, perché conta la tempestività.
- **La risposta si aggancia al passo**: per esempio "servizio che genera shell" seguito da "connessione esterna" è già una reverse shell confermata, e si interviene prima che l'attaccante cerchi la scalata.

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

## 13. Console web e consegna

- Una **console unica di famiglia**, che mostra i moduli installati: solo Vulpnix, solo Erinix o entrambi (vista integrata).
- **DB separati** per tool. La console non tocca i DB: li interroga tramite il canale locale di ciascun tool, in sola lettura e con il minimo indispensabile.
- Esportazione dei report in HTML, Markdown e JSON.
- La web app è anche **il bersaglio del VSPT** (vulnerability scanning e pen test) richiesto dalla consegna: sicurezza fin dal progetto (argon2, query parametrizzate, CSRF, header di sicurezza, limite ai login, escape di tutto l'input dai tool), riferimento OWASP Top 10, poi scansioni, test manuali, report e secondo test di verifica. Il laboratorio richiede HTTPS e autenticazione sull'interfaccia raggiungibile.

## 14. Rischi residui (da dichiarare nel report)

- La **console** vede entrambi i tool: è l'unico punto in cui si incontrano. Si riduce (sola lettura, utente proprio, niente accesso ai file), non si elimina.
- Un attaccante che ottiene **root** può fermare Erinix: l'obiettivo è **accorgersene** (sensore fermato come allarme), non impedirlo.
- Con eBPF il kernel può perdere eventi se il buffer si riempie: si contano e si dichiarano.
- Ogni regola ha falsi positivi possibili; le regole `auto` sono poche, motivate e revisionabili.

## 15. Piano di lavoro e date

- **6 novembre 2026**: sfida red team vs blue team (Raspberry). Erinix "da gara": sensore, poche catene solide, esche, risposta con scadenza e lista intoccabile, alert da terminale, nessuna console. Erinix è costruito per **qualsiasi Linux**, non su misura del Raspberry.
- **19 novembre 2026**: consegna finale (tool di risk assessment e applicazione web, con VSPT). Console Nemirix, integrazione con Vulpnix, valutazione degli incidenti, report.

Ordine di sviluppo: modello eventi e albero dei processi (fatto), regole (fatto), motore di correlazione, guardia e risposta, sensore eBPF, fallback auditd, esche, storage, console.

## 16. Registro delle decisioni

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

### Ancora da decidere o riconfermare

- Scala di gravità condivisa con Vulpnix (qui: `low`, `medium`, `high`, `critical`; va allineata allo schema di Vulpnix).
- Dati ostili: grezzi nel DB con escape in output (proposta adottata).
- Strato di caricamento eBPF da Python (libreria esistente o piccolo componente in C).
- Regolamento della sfida red vs blue (esche, blocchi IP, disponibilità dei servizi).
