# Footprinting, Fingerprinting, TLS Analysis & Deep Packet Inspection (Suricata)

Laboratorio pratico focalizzato sulla ricognizione attiva/passiva, l'analisi del traffico applicativo cifrato (TLS/JA3) e il rilevamento delle minacce tramite motore IDS/DPI Suricata.

## Strumenti e Tecnologie
* **Ricognizione & Fingerprinting:** `whois`, `dig`, `nslookup`, `Nmap` (`-O`, `-sV`), `p0f` (fingerprinting passivo), `curl`, `netcat`
* **Analisi Traffico & TLS:** `tcpdump`, `Wireshark`, `tshark` (estrazione fingerprint `JA3`)
* **IDS / Deep Packet Inspection:** `Suricata` (ruleset *Emerging Threats Open* + regole custom in `local.rules`)

---

## 1. Footprinting & Fingerprinting (`scanme.nmap.org`)
Attività svolta nel rispetto dei limiti etici e di autorizzazione su host pubblico predisposto per test didattici:
* **Ricognizione Passiva:** Raccolta informazioni su registrar, name server e record IP tramite `whois` e `dig` senza generare traffico diretto verso il bersaglio.
* **OS & Service Fingerprinting:** Correlazione tra l'output di `nmap -O` / `nmap -sV` e l'ispezione manuale dei pacchetti SYN in Wireshark (osservazione di **TTL iniziale**, dimensione della finestra TCP e opzioni *MSS/Window Scale/Timestamps*).
* **Passivo vs Attivo:** Il fingerprinting passivo (`p0f`, DNS/WHOIS) non invia pacchetti anomali al bersaglio e non lascia tracce nei log IDS/firewall, a differenza delle scansioni attive Nmap.

---

## 2. Analisi HTTP, Autenticazione Basic e Handshake TLS
Analisi del traffico applicativo tramite i *Wireshark Labs (UMass)*:
* **HTTP Basic Auth:** L'header `Authorization: Basic` non cifra le credenziali ma le codifica semplicemente in **Base64**, rendendole immediatamente leggibili in chiaro da chiunque intercetti il traffico.
* **Handshake TLS:** Verifica della sequenza `TCP 3-Way Handshake` $\rightarrow$ `Client Hello` (con estensione **SNI / Server Name Indication** per indicare il dominio richiesto prima della cifratura) $\rightarrow$ `Server Hello` + `Certificate` $\rightarrow$ `Change Cipher Spec` $\rightarrow$ `Application Data` cifrati.
* **JA3 Fingerprinting:** Estrazione dell'hash `JA3` tramite `tshark` dai parametri del *Client Hello* (versione TLS, cipher suite, estensioni). Confrontando `curl` e un browser web emergono hash JA3 distinti: questa tecnica permette ai sistemi difensivi (SOC/IDS) di identificare la tipologia di client o eventuali malware anche quando il payload è cifrato.

---

## 3. Deep Packet Inspection (DPI) con Suricata (`/rules`)
Configurazione di `Suricata` in modalità analisi offline su dataset misto (`mergecap`) e scrittura di firme personalizzate in `local.rules`:

```suricata
# 1. Rilevamento traffico ICMP di test
alert icmp any any -> any any (msg:"LAB3 - Traffico ICMP rilevato"; sid:1000001; rev:1;)

# 2. Rilevamento credenziali HTTP Basic Auth trasmesse in chiaro (Base64)
alert http any any -> any any (msg:"LAB3 - Credenziali HTTP Basic Auth in chiaro"; flow:to_server; http.header; content:"Authorization: Basic"; sid:1000002; rev:1;)

# 3. Rilevamento traffico verso dominio specifico tramite estensione TLS SNI
alert tls any any -> any any (msg:"LAB3 - Connessione TLS rilevata verso target monitorato"; tls.sni; content:"cics.umass.edu"; sid:1000003; rev:1;)
