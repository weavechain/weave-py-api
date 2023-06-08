## Weavechain Python API

[https://weavechain.com](https://weavechain.com): Layer-0 For Data

#### How to install

```sh
pip install weave-py-api
```

#### Data read sample

```python
from weaveapi import weaveapi
from weaveapi.records import *
from weaveapi.options import *
from weaveapi.weaveh import *

pub, pvk = generate_keys()
print("Public key: ", pub)
print("Private key:", pvk)

node = "https://public.weavechain.com:443/92f30f0b6be2732cb817c19839b0940c"
organization = "weavedemo"
scope = "shared"
table = "directory"

cfg = weave_client_config(pub, pvk, node, organization)
nodeApi, session = connect_weave_api(cfg)

reply = nodeApi.read(session, scope, table, None, READ_DEFAULT_NO_CHAIN).get()
print(reply["data"])
```

#### Docs

[https://docs.weavechain.com](https://docs.weavechain.com)