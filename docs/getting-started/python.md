# Install for Python

Python **3.9** or newer is required:

```bash title="Terminal"
python3 -m pip install tls-forge
```

The platform wheels include a transport binary. For a custom development binary:

```bash title="Terminal"
export TLSFORGE_BIN=/absolute/path/to/tls-forge
```

```python title="Python"
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    response = client.get("https://example.com/")
    print(response.status, response.body)
```

The SDK checks the daemon's engine identity before requests. Keep the package and executable on the same engine major. Continue with the [Python guide](../integrations/python.md) and [generated API reference](../reference/python-api.md).
