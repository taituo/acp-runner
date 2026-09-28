# acp-runner: korjaussuunnitelma

Sep 27, 2026 · @Tuomas

Kaikki 15 katselmointilöydöstä sekä vapaa käynnistysmäärittely ja AgentEnvironmentin tuotantokytkentä tehdään yhdessätoista vaiheessa, arviolta 28–38 kehittäjäpäivässä. Ensin CI luotettavaksi, sitten tilaustunnisteiden eheys (löydökset 1, 2 ja 5), sitten ingestin ja ympäristöjen oikeellisuus. Jokainen vaihe on oma PR, jossa on regressiotesti löydökselle.

## Etenemisjärjestys

&#91;embedded content: korjausvaiheet V0–V10 · riippuvuudet ja arviot kehittäjäpäivinä\]

V0 avaa tien kaikelle muulle. V1 ja V2 alkavat vasta, kun päätökset P1 ja P2 on tehty (ks. Avoimet päätökset). V4 rakentuu V1:n päälle ja V5 V3:n päälle. V6–V8 sopivat täytetyöksi. Numerot viittaavat katselmoinnin löydöksiin, arviot ovat karkeita kehittäjäpäiviä.

## Vaihe 0 – CI ja testit (1 pv)

CI:n pitää ajaa jokainen myöhempi regressiotesti deterministisesti, joten tämä tehdään ensin. Korjaa löydös 14.

**Muutokset**

- `crates/acp-runner-engine/tests/isolation.rs`: kutsu `build()` testin `proxy_egress_blocks_arbitrary_hosts_and_allows_the_allowlist` alussa. Nyt testi luottaa siihen, että rinnakkainen testi on jo rakentanut `acp-egress-proxy`-binäärin.
- `scripts/test.sh`: lisää `-p acp-egress-proxy -p acp-openai-shim` build-riville.
- `.github/workflows/ci.yml`: tee PostgreSQL- ja envtest-testeistä pakollisia. Aseta `ACP_REQUIRE_DB_TESTS=1`, jolloin `SKIPPED`-polku kaatuu virheeseen eikä ohitu hiljaa. Toteuta tarkistus testien yhteiseen apufunktioon.
- Lisää `cargo deny check` tai `cargo audit` omaksi CI-askeleekseen, koska muutokset koskevat kryptografiaa ja HTTP:tä.

**Hyväksyntä**

- `scripts/test.sh` menee läpi puhtaalta checkoutilta 10 kertaa peräkkäin (`cargo clean` välissä kerran).
- CI:n loki näyttää, että journal-, engine-e2e- ja kube-e2e-testit oikeasti ajettiin.

## Vaihe 1 – Credential write-back (5–7 pv)

Controller ei enää tallenna hiekkalaatikon kirjoittamaa `auth.json`:ia sellaisenaan. Se todentaa refresh tokenin itse providerilta ja tallentaa vain itse saamansa tokenit. Korjaa löydökset 1 ja 10.

Pelkkä JWT-allekirjoituksen tarkistus ei riitä. Agentilla on käytössään uhrin aito, allekirjoitettu id\_token, ja se voi liittää sen rinnalle oman refresh tokeninsa. Refresh token sidotaan tiliin vain käyttämällä sitä.

**1a. Todentava write-back (suositus nyt, päätös P1)**

1. Uusi moduuli `crates/acp-runner-engine/src/codex_refresh.rs` hoitaa OAuth-refreshin: token-endpoint, client id ja JWKS-osoite konfiguraatiosta. Arvot otetaan `drivers.lock.yaml`:iin pinnatun Codex-version lähdekoodista toteutushetkellä, ei muistinvaraisesti.
2. `post_credential` (`ingest.rs:494`) purkaa lähetetystä tiedostosta vain `refresh_token`:in ja tekee sillä refreshin. Vastauksen id\_tokenin allekirjoitus, `iss`, `aud` ja `exp` tarkistetaan JWKS:ää vasten.
3. Tilin sormenjälki lasketaan vain todennetusta claimista `chatgpt_account_id`. Selväkielinen `tokens.account_id` jätetään huomiotta (`credentials.rs:273`).
4. Store saa controllerin itse rakentaman `auth.json`:in. Jos refresh tai todennus epäonnistuu, write-back hylätään eikä profiilia muuteta. Metriikkaan `rejected{reason}`.
5. Controller tarvitsee egressin providerin auth-hostiin. Lisää se egress-proxyn allowlistiin ja controllerin NetworkPolicyyn.

**1b. Controllerin oma refresh (pitkän aikavälin tavoite)**

- Controller päivittää tokenit ennen leasea, ja hiekkalaatikko saa `auth.json`:in ilman käyttökelpoista refresh tokenia. Tällöin write-back poistuu kokonaan.
- Edellytys: compat-testi, joka osoittaa pinnatun Codexin toimivan ilman refresh tokenia koko attemptin ajan. Jos ei toimi, jäädään 1a:han.

**1c. Muut tilat ja reunaehdot**

- `personalAccessToken` ja `agentIdentity`: write-back pois. `validate_writeback` hylkää kaiken muun kuin `chatgpt`-tilan, ja attempt specin `writeback`-lippu asetetaan näille falseksi.
- Write-back terminoinnin jälkeen (löydös 10): credential-reitti hyväksyy myös terminaalivaiheen attemptin, jos lease on yhä vapauttamatta ja `finished_at` on alle 10 minuuttia sitten. `attempt_cleanup` vapauttaa leasen vasta, kun backend on vahvistanut sandboxin loppuneen.
- Lease-tarkistuksen ja store-päivityksen välinen kilpatilanne: lukitse lease-rivi (`FOR UPDATE`) transaktiossa, jonka aikana store päivitetään. Commit vasta onnistuneen päivityksen jälkeen.

**Testit**

- Katselmoinnin PoC-testit käännettyinä: väärennetty `account_id` ja PAT-vaihto hylätään.
- Axum-pohjainen väärennös-token-endpoint ja JWKS: oikea tili hyväksytään, toinen tili, virheellinen allekirjoitus ja roskatoken hylätään.
- Engine-e2e: cancel kesken ajon, write-back hyväksytään vielä terminaalivaiheessa.

**Hyväksyntä:** yksikään agentin kirjoittama tavu ei päädy credential storeen ilman providerin vahvistusta.

## Vaihe 2 – Profiilien ja runner-luokkien luottamusraja (3–4 pv)

Credential-profiili lainataan vain ajolle, jonka nimiavaruus ja luokka on profiilissa erikseen sallittu, ja vain allowlistatulla, digest-pinnatulla imagella. Korjaa löydös 2.

**Muutokset**

1. **Profiilin käyttöpolitiikka.** Migraatio `0006_profile_policy.sql` lisää tauluun `credential_profiles` sarakkeet `allowed_namespaces text[]` ja `allowed_classes text[]`. K8s-storessa ne tallennetaan Secretin annotaatioihin `acp-runner.dev/allowed-namespaces` ja `acp-runner.dev/allowed-classes`.
2. `Journal::start_attempt` (`journal/src/lib.rs:430`) tarkistaa ehdokasprofiilin politiikan ajon nimiavaruutta ja luokkaa vasten. Hylkäys palauttaa `CredentialUnusable`-tuloksen ja syyn.
3. Oletus on kieltävä: tyhjä lista ei salli mitään. `acp-runnerctl auth enroll` ja uusi `auth allow` saavat liput `--allow-namespace` ja `--allow-class`.
4. **Image-politiikka.** Controllerin asetus `ACP_RUNNER_ALLOWED_IMAGES` (lista `repo@sha256:…`). Tunnisteita käyttävän luokan image on oltava listalla ja digestillä pinnattu, muuten ajo epäonnistuu `Unsupported`-syyllä ennen leasea.
5. **Service account.** `serviceAccountName` hyväksytään vain controllerin allowlistalta (`ACP_RUNNER_ALLOWED_SERVICE_ACCOUNTS`). Oletus on nykyinen `acp-runner-agent`.
6. Jos päätös P2 on ”vain ylläpitäjät”, lisätään klusteritason `ACPClusterRunnerClass`. Tunnisteita käyttävä luokka sallitaan silloin vain sen kautta, ja nimiavaruuskohtaiset luokat rajataan tunnisteettomiin ajureihin.
7. README: uusi luku ”Luottamusmalli”, jossa kerrotaan, kuka on luotettu (profiilin ylläpitäjä, luokan kirjoittaja, ajon luoja) ja mitä kukin voi tehdä.

**Siirtymä:** olemassa olevat profiilit lakkaavat toimimasta, kunnes niille annetaan politiikka. Julkaisutiedotteeseen `acp-runnerctl auth allow` -ohje.

**Testit**

- Journal: profiili, joka on sallittu vain nimiavaruudelle A, hylätään nimiavaruuden B ajolta.
- Kube-e2e: pinnaamaton image johtaa `Unsupported`-syyhyn, ja kiellettyyn SA:han viittaava luokka hylätään.

**Hyväksyntä:** käyttäjä, jolla on vain ACPRun- ja ACPRunnerClass-oikeudet omassa nimiavaruudessaan, ei saa minkään profiilin tunnistetta itse valitsemaansa imageen.

## Vaihe 3 – Ingestin eheys (2 pv)

Ingest hyväksyy vain attemptin omat artefaktit ja vain runnerd:n lähettämät luottamusta vaativat kategoriat. Korjaa löydökset 3 ja 4.

**3a. artifactId-sidonta (löydös 3)**

- `post_events` (`ingest.rs:367`): ennen `set_attempt_details`-kutsua haetaan `artifacts.get_meta(id)` ja vaaditaan `attempt_id == a.id` sekä `run_id == a.run_id`. Jos ehto ei täyty, attempt päätetään `ProtocolError`-syyllä eikä artefaktia liitetä.
- Sama tarkistus `finalArtifactId`:lle (`engine/environment.rs:729`) ja `snapshot_created`-eventin `artifactId`:lle.
- Tietokantatason varmistus: trigger tauluun `attempts`, joka tarkistaa, että asetettu `artifact_id` kuuluu samaan attemptiin (migraatio `0007`).

**3b. Varatut Progress-kategoriat (löydös 4)**

1. `acp-runner-core/src/events.rs`: vakio `RUNNER_OWNED_CATEGORIES` (`workspace_ready`, `gateway_listening`, `environment_ready`, `environment_busy`, `turn_ended`, `snapshot_*`, `credential_writeback*`, `timeout`, `agent_*`).
2. runnerd (`supervisor.rs:254`, `environment.rs:96`): agentilta tuleva Progress, jonka kategoria on varattu, nimetään muotoon `agent.<kategoria>` ja siitä journaloidaan `protocol_warning`.
3. Ingest hylkää erän, jossa on `source = agent` ja varattu kategoria.
4. Kuluttajat suodattavat myös itse `source = runnerd`: `ingest.rs:337`, `engine/environment.rs:718, 753, 852, 928`.

**Testit:** ingest-testi, jossa vieraan ajon `artifactId` hylätään. Engine-testi, jossa agentin `gateway_listening`- ja `workspace_ready`-eventit eivät muuta yhteysosoitetta tai base-revisionia.

## Vaihe 4 – Bootstrap-eristys (2–3 pv)

Tunnisteet sijoitetaan HOMEen vasta, kun bootstrap on valmis eikä yksikään bootstrap-prosessi ole enää käynnissä. Korjaa löydös 5 ja rakentuu vaiheen 1 päälle.

**Muutokset**

1. `bins/runnerd/src/home.rs`: jaa `prepare_home` kahteen osaan. `prepare_home_base` luo hakemistot, ja `place_credentials` kirjoittaa tiedostot ja staged-env-tiedostot.
2. `bins/runnerd/src/environment.rs`: kun `bootstrap` ei ole tyhjä, `place_credentials` kutsutaan `BootstrapDone`-viestin jälkeen ja ennen `Proceed`-viestiä. Ilman bootstrappia järjestys pysyy ennallaan.
3. `bins/agentd/src/main.rs`: `take_staged_credentials` siirretään `run_bootstrap`-kutsun jälkeen, jolloin staged-tiedostot luetaan vasta `Proceed`-viestin jälkeen.
4. Prosessipuu: agentd asettaa itselleen `PR_SET_CHILD_SUBREAPER`-lipun. Jokaisen bootstrap-askeleen jälkeen se tappaa ja korjaa kaikki jälkeläiset. Jos taustaprosesseja jäi, tuloksena on `BootstrapFailed` (”left background processes”).
5. Jos bootstrap on luonut tiedoston tunnisteen kohdepolkuun, `write_beneath` kaatuu jo nyt `O_EXCL`-lipun takia. Syy raportoidaan selvästi muodossa `WorkspacePolicyViolation`.
6. Korjaa harhaanjohtava kommentti `agentd/src/main.rs:390` kuvaamaan uutta järjestystä.

**Lisäys, bootstrap-askeleen `cwd`:** agentd yhdistää nyt normalisoidun polun työtilaan tarkistamatta symlinkkejä. Tietoturvavaikutus on pieni, koska bootstrap-komento voi joka tapauksessa vaihtaa hakemistoa itse. Johdonmukaisuuden vuoksi cwd avataan kuitenkin samalla `O_NOFOLLOW`-askelluksella kuin `workdir` ja otetaan käyttöön `fchdir`-kutsulla juuri ennen `execve`-kutsua. Tarkistusta ei tehdä runnerd:ssä etukäteen, koska aiempi bootstrap-askel voi muuttaa symlinkin tarkistuksen ja suorituksen välissä.

**Testit (`engine/tests/environment_provider.rs`)**

- Bootstrap-askel, joka yrittää lukea `~/.codex/auth.json`:ia, ei löydä sitä.
- Askel `sh -c 'sleep 600 &'` johtaa `BootstrapFailed`-syyhyn, eikä prosessia ole enää olemassa harnessin käynnistyessä.

## Vaihe 5 – Ympäristön ohjaus ja skaalautuvuus (3–4 pv)

Ympäristön ohjauskomennot tallennetaan PostgreSQL:ään, ja tila johdetaan kohdennetuilla kyselyillä 100 000 eventin skannauksen sijaan. Korjaa löydökset 6 ja 7. Tämä on edellytys AgentEnvironment-reconcilen kytkemiselle controlleriin.

**5a. Pysyvä direktiivijono (löydös 7)**

1. Migraatio `0008_env_directives.sql`: taulu `environment_directives (id uuid, attempt_id uuid, directive jsonb, created_at, delivered_at, acked_at)`.
2. `push_env_directive` kirjoittaa tauluun. `post_heartbeat` palauttaa vanhimman kuittaamattoman direktiivin ja merkitsee `delivered_at`-ajan (`ingest.rs:407`).
3. runnerd kuittaa direktiivin id:llä (esimerkiksi `snapshot_created` + `directiveId`). Uudelleentoimitus tapahtuu, jos kuittausta ei tule 2 heartbeat-välin kuluessa. Snapshot-id tekee käsittelystä idempotentin.
4. Cancel tarkistetaan ennen jonoa, jotta peruutus ei odota jonossa olevan snapshotin takana.
5. `hb_last` korvataan sarakkeella `attempts.last_heartbeat_journaled_at`, jolloin prosessin muistiin ei jää mitään attemptikohtaista.
6. Poista `controller.rs:3–5`:n väite useiden replikoiden turvallisuudesta, kunnes tämä vaihe on tehty, ja lisää se takaisin testin kanssa.

**5b. Kohdennetut kyselyt (löydös 6)**

- Uudet journal-funktiot: `latest_runner_progress(attempt, categories[])` ja `progress_by_detail(attempt, key, value)`. Kyselyt ovat muotoa `WHERE kind='Progress' AND source='runnerd' AND data->>'category' = ANY($2)`, ja ne ottavat vain uusimman rivin kategoriaa kohden.
- Indeksi `(attempt_id, kind, (data->>'category'))`.
- `refresh()` ja `snapshot_and_wait` (`engine/environment.rs:716, 851`) käyttävät näitä. Tilaa voi lisäksi pitää yllä `environments`-rivillä kursorina (`last_event_id`).

**Testit**

- Kahden ingest-instanssin testi: direktiivi lisätään instanssin A kautta ja toimitetaan instanssin B heartbeatiin.
- Suorituskykytesti: 200 000 eventin ympäristössä `refresh()` pysyy alle 50 ms:n.

## Vaihe 6 – Patchin hygienia (1 pv)

Patch ei saa sisältää gitlinkejä eikä `.gitmodules`-muutoksia, ellei ajo erikseen salli niitä. Korjaa löydös 8.

- `crates/acp-runner-workspace/src/lib.rs`: laajenna `parse_symlinks` yleiseksi `parse_modes`-funktioksi. Tila `160000` (gitlink) johtaa `WorkspaceError::Policy`-tgvirheeseen.
- `.gitmodules`-polun muutos on policy-virhe, ellei `OutputSpec`:ssä ole uutta kenttää `allowSubmodules: true` (oletus false).
- `.git`-segmentin tarkistus kirjainkoosta riippumattomaksi (`.GIT`, `.Git`), jotta patch on turvallinen myös macOS- ja Windows-kuluttajille.
- `ChangedPath` saa kentän `mode`, jotta kuluttaja näkee suoritusoikeusmuutokset.
- Indeksitiedostojen nimet (`collect-{pid}.index`, `fingerprint-{pid}.index`) vaihdetaan kutsukohtaisiksi (`Uuid::new_v4`), jolloin samanaikaiset keruut eivät törmää.

**Testit:** sisäkkäinen `git init` työpuussa johtaa policy-virheeseen, `.gitmodules`-muutos hylätään oletuksena, ja kaksi rinnakkaista `collect_patch`-kutsua tuottavat identtiset patchit.

## Vaihe 7 – Verkko: egress-proxy ja NetworkPolicy (1–2 pv)

Proxy kokeilee kaikkia resolvoituja osoitteita ja tunnistaa epäjulkisiin IPv4-osoitteisiin kääntyvät IPv6-alueet. NetworkPolicyn poikkeuslistat päivitetään vastaamaan. Korjaa löydös 9.

**`bins/acp-egress-proxy/src/lib.rs`**

- `is_public` (`:101`): lisää NAT64 `64:ff9b::/96` ja `64:ff9b:1::/48` (upotettu IPv4 tarkistetaan), 6to4 `2002::/16` (upotettu IPv4 tarkistetaan), Teredo `2001::/32`, site-local `fec0::/10`, discard `100::/64` sekä IPv4 `192.88.99.0/24`. Taulukkotestit kullekin.
- `handle` (`:306`): yhdistä osoitteisiin vuorotellen, kukin omalla aikakatkaisullaan, kunnes yksi onnistuu. Lokiin tieto siitä, mikä osoite käytettiin.
- Tavulaskurit säilyvät myös `max_tunnel`-aikakatkaisussa: käytä omaa kopiosilmukkaa laskureineen `copy_bidirectional`-kutsun sijaan.

**`deploy/agents/networkpolicy.yaml` (direct-tila)**

- IPv4-poikkeuksiin `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4` ja `240.0.0.0/4`.
- IPv6-poikkeuksiin `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16` ja `fec0::/10`.

**Testit:** `decide` hylkää nimen, joka resolvoituu osoitteeseen `64:ff9b::a00:1`. Proxy yhdistää, kun ensimmäinen osoite ei vastaa ja toinen vastaa.

## Vaihe 8 – Pienemmät korjaukset (2 pv)

Loput neljä löydöstä ovat itsenäisiä ja sopivat yhteen siivous-PR:ään tai täytetyöksi.

| Löydös | Muutos | Tiedostot | Testi |
| --- | --- | --- | --- |
| 11 Redaktointi | Credential-tiedoston jokainen JSON-merkkijonolehti (vähintään 8 merkkiä) lisätään literaaliksi koko tiedoston sijaan. Samoin write-backin uudet arvot ja gatewayn `K_env`. | `runnerd/src/home.rs:272`, `core/src/redact.rs` | Refresh token ilman `rt_`-etuliitettä redaktoituu |
| 12 Gateway | Vaihetarkistus ennen noncen kuluttamista. Semafori samanaikaisille handshakeille (esim. 32). Tavut välitetään `Vec<u8>`:nä, ja virheellinen UTF-8 hylätään `from_utf8_lossy`-muunnoksen sijaan. | `runnerd/src/gateway.rs:253–266, 330–335` | 409-vastauksen jälkeen sama lipuke kelpaa; 100 roikkuvaa yhteyttä ei estä oikeaa |
| 13 `file://` | Sallitaan vain, kun controllerin asetus `ACP_RUNNER_ALLOW_FILE_REPOS=true`. `dev-run` ja testit asettavat sen. | `core/src/spec.rs:398`, `engine` | Spec, jossa `file://`, hylätään oletusasetuksilla |
| 15 Dokumentaatio ja siivous | README:n alkuun maininta, ettei AgentEnvironment-reconcilea ole kytketty. Poista client-puolelta tehoton `uploadpack.allowAnySHA1InWant`. | `README.md`, `workspace/src/lib.rs:147` | – |

**Lisäykset toisesta katselmoinnista:**

- **Gatewayn täysi läpinäkyvyys:** `ws_to_line` (`gateway.rs:303`) parsii ja serialisoi JSONin uudelleen, jos WebSocket-kehyksessä on rivinvaihtoja. Rivinvaihto voi JSONissa olla vain merkkijonojen ulkopuolista välilyöntiä, joten tilalle tulee tavutason korvaus välilyönnillä ilman parsintaa. Avainjärjestys, numeroiden esitys ja kaksoisavaimet säilyvät. Testissä sama sisältö menee läpi tavu tavulta, kehystyksen erotinta lukuun ottamatta.
- **Enintään yksi PatchArtifact-overlay:** artefaktit ovat kumulatiivisia baseen nähden, joten kahden patchin peräkkäinen soveltaminen lupaisi merge-semantiikan, jota ei ole määritelty. Validointi (`core/src/environment.rs`) sallii korkeintaan yhden overlayn, ja rakenne pysyy listana tulevaa käyttöä varten.

## Vaihe 9 – Vapaa käynnistysmäärittely ja ACP-profiilin tunnistus (3–4 pv)

Agentin käynnistys määritellään kokonaan CRD:ssä komentona, argumentteina, ympäristönä ja tiedostoina. acp-runner ei mallinna CLI:iden lippuja: malli, luottamus- ja päivitysasetukset ovat pelkkiä käynnistysparametreja. ACP-toteutusten erot selvitetään testaamalla ja tallennetaan profiiliksi.

**Muutokset**

1. **Yleinen `acp`-ajuri.** Nykyinen `AcpDriver` lukee jo komennon, argumentit ja ympäristön, mutta sitä käytetään vain `fake`-ajurille. Se rekisteröidään myös nimellä `acp`, jolloin `command` on pakollinen. Mikä tahansa stdion yli ACP:tä puhuva CLI toimii ilman koodimuutosta.
2. **Yksi pieni primitiivi, yhdessä paikassa:** `launch {command, args[], env{}, files[], cwd}`. Se määritellään runner-luokassa (`driver: acp`) ja AgentEnvironmentissa muodossa `harness: {name: acp, config: <launch>}`. Nimetyt harnessit (`codex`, `claude`) ratkaistaan HarnessProviderissa samaksi primitiiviksi. `files` sijoittaa konfiguraatiotiedostot HOMEen `replace_beneath`-funktiolla.
3. **Ajokohtaiset lisäykset vain kahdessa muodossa:** `ACPRun.spec.overrides.env` ja `.files`, ja vain jos luokassa on `allowRunOverrides: true`. Avain korvaa avaimen, eikä listoja yhdistetä tai argumentteja lisätä. Näin merge-kerroksia ei synny, ja ajokohtainen malli annetaan ympäristömuuttujana tai konfiguraatiotiedostona.
4. **Rajat:** ajokohtainen muutos ei laajenna oikeuksia, koska komento ajetaan joka tapauksessa epäluotettavassa agentd:ssä. runnerd:n omat muuttujat (HOME, XDG, proxy) asetetaan viimeisinä, proxy-tilan NetworkPolicy pätee joka tapauksessa, ja tunnisteet saa vain vaiheen 2 politiikan kautta.
5. **Yleinen tunnisteprovider `files`:** profiili koostuu nimetyistä tiedostoista, ja kohdepolut annetaan olemassa olevalla `fileTargets`-kentällä. Enrollment voi poimia JSON-tiedostosta vain valitut merkinnät (`--select openai`). Write-backia ei ole.
6. **ACP-profiilin tunnistus:** `initialize`-vastaus (protokollaversio, `agentCapabilities`, `authMethods`) journaloidaan aina. Uusi `acp-conformance`-sarja testaa minkä tahansa launch-määrittelyn:
   - cancel, permission-pyynnöt, työkalupäivitykset ja `usage`
   - `session/load` ja mallinvaihto
   - käyttäytyminen, kun stdin suljetaan
   - käynnistysaika ja verkkoyhteydet käynnistyksessä

   Tulos tallennetaan profiiliksi tiedostoon `drivers.lock.yaml`, ja agentd käyttää sitä vain havaittuihin eroihin.
7. **Interaktiiviset kyselyt:** ACP-tilassa luottamus- ja lupakyselyt tulevat `session/request_permission`-viesteinä, ja agentd vastaa niihin itse. Päivitystarkistukset kytketään pois launch-ympäristöllä tai -tiedostoilla. Conformance-sarja näkee, jos CLI silti odottaa syötettä tai yrittää verkkoon käynnistyessään.

**Testit:** testaussuunnitelman tapaukset A21–A24 ja `acp-conformance`.

## Vaihe 10 – AgentEnvironmentin tuotantokytkentä (5–8 pv)

AgentEnvironment-CRD on olemassa, mutta controller seuraa vain ACPRun-resursseja. Tässä vaiheessa ympäristöt kytketään controlleriin niin, että ne kestävät controllerin uudelleenkäynnistykset ja pitkät katkot. Rakentuu vaiheen 5 pysyvän direktiivijonon päälle.

**10a. Reconcile, status ja finalizer**

1. Controller seuraa `AgentEnvironment`-resursseja. Luonti, muutos ja poisto kutsuvat `EnvironmentProvider`-rajapintaa, ja finalizer siivoaa sandboxin, leasen ja Servicen.
2. Status: vaihe, endpoint, ratkaistu revisio, lineage ja virhe.
3. `finish`, `cancel` ja `destroy` toimivat myös controllerin uudelleenkäynnistyksen yli, koska tila on PostgreSQL:ssä.
4. Gatewaylle luodaan ympäristökohtainen Service sekä NetworkPolicy, joka sallii ingressin vain kutsujan nimiavaruudesta.

**10b. Pysyvä ticket-avain**

- Master key luetaan Kubernetes Secretistä `TicketKey::from_file`-funktiolla. Funktio on jo olemassa, mutta mikään binääri ei kutsu sitä.
- Kaikki replikat käyttävät samaa avainta, ja avaimen kierto hoidetaan tukemalla kahta avainta yhtä aikaa.
- Hyväksyntä: uusi controller-replika minttaa lipukkeen ympäristöön, jonka edellinen replika loi.

**10c. Lease ei vanhene elävän sandboxin alta**

Nyt ympäristön lease on 15 minuutin ikkuna (`credential_lease_window`), jota heartbeat jatkaa. Ympäristö voi kuitenkin elää tunnin, eikä runnerd pysähdy, vaikka heartbeat epäonnistuu. Jos controller on alhaalla yli 15 minuuttia, sama yksinoikeudellinen tunniste voidaan lainata toiselle ympäristölle.

- Leasen kesto sidotaan sandboxin kovaan takarajaan (`maxSeconds` + käynnistys + grace + marginaali), ja pod saa saman `activeDeadlineSeconds`-arvon. Heartbeat on vain optimistinen jatko, ei turvallisuuden perusta.
- Vanhentunutta yksinoikeudellista leasea ei anneta uudelle haltijalle ennen kuin backend on vahvistanut edellisen sandboxin päättyneen (fencing).
- runnerd pysäyttää agentin, jos heartbeat on epäonnistunut yhtäjaksoisesti leasen jäljellä olevan ajan verran.
- Hyväksyntäkriteeri: yksinoikeudellista profiilia ei voi lainata toiselle ympäristölle niin kauan kuin edellisen sandboxin päättymistä ei ole todettu authoritative-tasolla.

**10d. End-to-end:** `kubectl apply AgentEnvironment` → Ready → ACP-yhteys → snapshot → finish, oikeassa klusterissa.

## Avoimet päätökset

Kolme päätöstä pitää tehdä ennen vaiheita 1 ja 2. Muut vaiheet voivat edetä niitä odottamatta.

- [ ] **P1 – Write-backin malli.** Suositus: 1a nyt ja 1b myöhemmin, jos compat-testi osoittaa Codexin toimivan ilman refresh tokenia. Kumpikin vaatii controllerille egressin providerin auth-hostiin. Onko se hyväksyttävä teidän verkkomallissanne?
- [ ] **P2 – Kuka saa kirjoittaa tunnisteita käyttäviä runner-luokkia?** Vaihtoehdot: (a) vain ylläpitäjät klusteritason `ACPClusterRunnerClass`-resurssin kautta, tai (b) nimiavaruuksien käyttäjät profiilipolitiikan ja image-allowlistin rajoissa. Monikäyttäjäympäristössä suositus on (a).
- [ ] **P3 – Olemassa olevien profiilien siirtymä.** Kieltävä oletus heti (suositus, koska kyse on tietoturvakorjauksesta) vai yhden julkaisun ajan varoitus ja sen jälkeen kielto?

## Valmiin määritelmä

Kokonaisuus on valmis, kun jokaisella 15 löydöksellä on regressiotesti, joka kaatuu ilman korjausta ja menee läpi korjauksen kanssa.

- [ ] `scripts/test.sh` menee läpi CI:ssä PostgreSQL- ja envtest-testit mukaan lukien, ilman yhtään `SKIPPED`-riviä.
- [ ] Katselmoinnin kaksi write-back-PoC-testiä on lisätty pysyviksi testeiksi hylkäävällä odotuksella.
- [ ] KIND-läpikulku (`scripts/e2e-kind.sh`) ja image-smoke (`scripts/compat-image.sh`) on ajettu kerran oikeassa klusterissa. README:n mukaan niitä ei ole vielä koskaan ajettu.
- [ ] README:n luvut 8, 13, 14 ja 18 (tietoturvatestien kartta) on päivitetty vastaamaan uutta luottamusmallia.
- [ ] Ulkopuolinen tarkastaja käy läpi vaiheiden 1 ja 2 PR:t ennen yhdistämistä.
- [ ] Julkaisutiedotteessa mainitaan rikkovat muutokset: profiilipolitiikka (V2), image-allowlist (V2) ja `file://`-oletus (V8).

Korjausten jälkeinen testaus, opencode-ajuri ja testbed-repo: Testaussuunnitelma
