import json, struct, subprocess, sys

RPC = "http://127.0.0.1:9711"
TX_EPOCH_BLOCKS = 32

def call(method, params=None):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []})
    out = subprocess.run(["curl","-s","-m","60","-X","POST",RPC,
                          "-H","content-type: application/json","-d",body],
                         capture_output=True).stdout
    r = json.loads(out)
    if "error" in r:
        raise SystemExit(f"{method} failed: {r['error']}")
    return r["result"]

# The terminal names the height it proves; pair the headers to THAT, not to the
# current tip, or validate_local_header_boundary rejects on height.
terminal = call("jetsam_getHistoryStepTerminal")
raw = bytes.fromhex(terminal)
wire_version = raw[0]
height = struct.unpack_from("<Q", raw, 1)[0]
anchor_height = 0 if height == 0 else ((height - 1) // TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS

header   = call("jetsam_getHeaderByHeight", [height])
epoch_hd = call("jetsam_getHeaderByHeight", [anchor_height])
info     = call("jetsam_getChainInfo")

json.dump({
    "wire_version": wire_version,
    "terminal_height": height,
    "epoch_anchor_height": anchor_height,
    "tip_height": info["height"],
    "terminal": terminal,
    "header": header,
    "epoch_header": epoch_hd,
}, sys.stdout)
