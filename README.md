# nex (Python)

Port Python de [PretendoNetwork/nex-go](https://github.com/PretendoNetwork/nex-go) (branche `splatoon`).
Aucune dépendance : bibliothèque standard uniquement (Python ≥ 3.10).

## Correspondance Go → Python

| Go | Python |
|---|---|
| `Bytes()` | `to_bytes()` |
| getters/setters (`SetPID`, `PID()`) | attributs (`client.pid`) |
| `(valeur, error)` | exception `NexError` |
| `NewServer()`, `NewClient(...)` | `Server()`, `Client(...)` |
| `nex.Errors.Core.Unknown` | `nex.Errors.Core.Unknown` |
| `server.On("Data", func(p *PacketV1){})` | `server.on("Data", lambda p: ...)` |
| goroutines / `time.AfterFunc` | `threading.Thread` / `threading.Timer` |
| `crypto/rc4` | `nex.RC4` (réimplémenté, stdlib n'en a pas) |

Fichiers : un module par fichier Go (`md5.go` + `sum.go` + `init.go` → `utils.py`).

## Exemple

```python
import nex

server = nex.Server()
server.prudp_version = 1
server.nex_version = 30500
server.access_key = "ridfebb9"

server.on("Data", lambda packet: print(packet.rmc_request.protocol_id))
server.listen(":60000")
```

## Tests

```
python -m unittest discover -s tests
```
