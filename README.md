# homeX - home IDS system


## Informacje ogólne

Projekt został stworzony na potrzeby realizacji pracowni inżynierskiej


## Twórcy

* Marcin Latawiec (311031)

## Elementy systemu

* Centralna aplikacja CLI
* Zdalny Logger Agentów
* Zdalny Agent

### Aplikacja

Centralna aplikacja odpowiada za sterowanie całym systemem, z jej poziomu użytkownik może wykonywać operację wczytywania poszczególnych plików, które następnie będą podlegały analizie. 
Aplikacja jest skomunikowana ze zdalnym agentem, poprzez ustanowiony kanał komunikacji możemy zarządzać agentem i wykonywać na nim różnego rodzaju operacje — tryb analizy online. 
Wyprowadzona została również komunikacja ze zdalnym loggerem, dzięki czemu uzyskany jest dostęp do logów praktycznie z dowolnego miejsca.

### Zdalny Agent

Zdalny agent jest kluczowym elementem naszego rozwiązania. 
Umożliwia zdalne wykonywanie licznych operacji monitorujących poprzez aplikację centralną. 
Łączy się z centralną aplikacją poprzez styk REST. 
Wykonuje odpowiednie komendy odebrane z aplikacji i zwraca żądane wartości, wyniki wykonania lub całe pliki z powrotem do centralnej aplikacji.

## Setup

Aby skonfigurować całe środowisko działania naszego rozwiązania, należy utworzyć dwa kontenery (lub inne hosty w zaawansowanym przypadku) i z trzeciego hosta uruchomić centralną aplikację Cliapp.

### Uruchomienie hosta z agentem

Uruchomienie agenta na danym hoście wymaga wpierw przekopiowania całego folderu *agent_files* do wybranego katalogu razem ze skryptem *agent.py*, a następnie uruchomienie tego skryptu. 
Należy się także upewnić, że port 8003 pozostanie otwarty, tak, aby nasza centralna aplikacja mogła się z nim skomunikować.
Warto też zwrócić szczególną uwagę na konieczność zainstalowania wpierw odpowiednich bibliotek wymaganych do uruchomienia agenta, które wskazane zostały w pliku *libraries.txt*.
Przykładowo na potrzeby tego zadania przygotowaliśmy plik Dockerfile umożliwiający wygodne wdrożenie kontenera z uruchomionym agentem.

1. Najpierw należy zbudować obraz kontenera:
```shell
> docker build ./agent -t agent
```
2. Następnie wystarczy uruchomić wspomniany obraz, upewniając się, że port 8003 zostanie otwarty.
```shell
> docker run -p 8003:8003 agent
```

## Obsługa aplikacji 

Aplikację wywołujemy poleceniem `python3 ./cliapp/app/main.py`. Wymaga ona jednak konkretnych argumentów, które będą precyzowały czynność, jaka ma zostać wykonana.
Zasadniczo podstawowe polecenie należy przekazać jako pierwszy argument, natomiast wszystkie parametry dotyczące wybranego polecenia należy podać po odpowiednim tagu określającym dany parametr, jako następne argumenty w dowolnej kolejności.
Przykładowo wykonanie odczytu pliku tekstowego będzie wyglądało następująco:
```shell
> python3 ./cliapp/app/main.py read-file --file_path ./agent/libraries.txt
```

Warto zwrócić uwagę, że w przypadku używaniu wszelkich zadań operujących na agencie kluczowe jest podanie tagu `--agent_host` razem z adresem i portem agenta.
Przykładowo wykonanie zdalnej komendy *netconfig* na agencie będzie wyglądało następująco:
```shell
> python3 ./cliapp/app/main.py agent --action netconfig --agent_host 172.17.0.1:8003
```

### Dostępne komendy i ich parametry

#### Komenda "read_file"

Dostępne parametry w ramach tej komendy:
```shell
--file_path
        # Ten parametr oznacza podanie ścieżki do pliku, który ma zostać wczytany. 
        # Jest konieczny w tej metodzie.

--re_pattern
        # Ten parametr umożliwia podanie wyrażenia regularnego, 
        # które zostanie zastosowane do wyświetlenia wybranego pliku 
        # we fragmentach pasujących do wyrażenia.

--grep_pattern
        # Ten parametr umożliwia podanie wyrażenia rozpoznawalnego programowi grep, 
        # które zostanie zastosowane do wyświetlenia wybranego pliku 
        # we fragmentach pasujących do wyrażenia.
        
--bpf_filter
        # Ten parametr umożliwia podanie filtru BPF, 
        # który zostanie zastosowany do wybranego pliku pcap.
```

#### Komenda "agent"

Dostępne parametry w ramach tej komendy:
```shell
--action [netconfig | capture | list_pcaps | list_logs | download_pcap | download_log | command]
        # Jest konieczny w tej metodzie.
        # Jest konieczny w tej metodzie.
--agent_host
        # Kluczowy parametr odpowiadajacy za poprawne połączenie się z agentem.
        # Jest konieczny w tej metodzie.
--interface
        # Parametr używany przy wyborze akcji "capture".
        # Określa interfejs sieciowy z którego chcemy przechwytywać zdarzenia.
--capture_filter
        # Parametr używany przy wyborze akcji "capture".
        # Określa filtr używany podczas przechwytywania zdarzeń.
--timeout
        # Parametr używany przy wyborze akcji "capture".
        # Określa czas przez który chcemy przechwytywać zdarzenia.
--file_number
        # Parametr używany przy wyborze akcji "download_pcap" i "download_log".
        # Pozwala wybrać plik do pobrania według numeracji z odpowiedniej akcji list.
--command
        # Parametr używany przy wyborze akcji "command".
        # Pozwala przekazać dowolną komendę do wykonania w bash przez agenta.
```

#### Komenda "loaddetectionrules"

Dostępne parametry w ramach tej komendy:
```shell
--file_path
        # Ten parametr oznacza podanie ścieżki do pliku, który ma zostać wczytany. 
        # Jest konieczny w tej metodzie.

--rule [detect_ip | detect_words | detect_anomaly]
        # Również konieczny parametr definiujący regułę analityczną.
```
Opis reguł dostępnych do wyboru:
* detect_ip - detekcja regułowa po ip znajdującym się w pliku *ip_blacklist.txt*. W przypadku wykrycia w badanym pliku pcap, określonego adresu IP aplikacja ma za zadanie wysłać alert.
* detect_words - detekcja regułowa po wyrazach znajdujących się w pliku *word_blacklist.txt*. W przypadku wykrycia w badnym pliku pcap, określonego wyrazu aplikacja ma za zadanie wysłać alert.
* detect_anomaly - detekcja oparta na sprawdzeniu w przechwyconym ruchu sieciowym niezaufanych portów komunikacji.

## Link do repozytorium GitLab

```shell
git clone https://gitlab-stud.elka.pw.edu.pl/mjjk/2022z_pythonblueteam.git
```
