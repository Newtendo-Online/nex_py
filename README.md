<h1 align="center">nex_py</h1>

<p align="center">
  <b>Implementation of Nintendo's NEX/PRUDP online protocol, written in Python.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python">
</p>

## Example

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
