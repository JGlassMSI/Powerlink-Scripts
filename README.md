You must be connected to a network segment that routes to the powerlink subnet (10.58.3.0/24) 

Uses `write_single_coil` not `write_register`, which does make a difference based on the target.

The manual control of coils is coils 3600 and up (3600 is breaker 1)

Uses [pyModbusTCP](https://pypi.org/project/pyModbusTCP/)

The full register/coil/address list is in `G4Control Module Register List _Public v1` in this repo as an XLSX file.