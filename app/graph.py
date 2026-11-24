"""Layer 10: scam-network graph. Domains are linked through shared TLS certificates, IPs, nameservers, favicon
hashes, phone numbers, form POST targets and redirect hops (correlation idea adapted from FraudLand correlation/engine.py: shared
infrastructure is an investigative lead, not proof)."""
import networkx as nx

from app import store

KIND_LABEL = {"cert": "TLS certificate", "ip": "IP", "ns": "Nameserver", "favicon": "Favicon hash", "phone": "Phone",
              "post_target": "Form target", "redirect_target": "Redirect target", "redirect_from": "Redirect via"}


def build() -> nx.Graph:
    scans, ents = store.graph_rows()
    g = nx.Graph()
    for s in scans:
        g.add_node(f"d:{s['registrable']}", kind="domain", label=s["registrable"], score=s["score"], fraud=s["label"] == "fraud",
                   scan_id=s["id"])
    for e in ents:
        dn = f"d:{e['registrable']}"
        if dn not in g:
            continue
        if e["kind"] == "redirect_target" and e["value"] == e["registrable"]:
            continue
        an = f"{e['kind']}:{e['value']}"
        if e["kind"] in ("redirect_from",):
            continue
        g.add_node(an, kind=e["kind"], label=e["value"])
        g.add_edge(dn, an, kind=e["kind"])
    # keep only attribute nodes that connect 2+ domains, plus every domain
    for n in [n for n, d in g.nodes(data=True) if d["kind"] != "domain" and g.degree(n) < 2]:
        g.remove_node(n)
    return g


def to_json(min_component: int = 1) -> dict:
    g = build()
    nodes, edges, campaigns = [], [], []
    for comp in nx.connected_components(g):
        doms = [n for n in comp if g.nodes[n]["kind"] == "domain"]
        if len(comp) < min_component:
            continue
        if len(doms) > 1:
            fraud = sum(1 for n in doms if g.nodes[n]["fraud"])
            campaigns.append({"domains": sorted(g.nodes[n]["label"] for n in doms), "fraud_domains": fraud,
                              "shared": sorted({f"{KIND_LABEL[g.nodes[n]['kind']]}: {g.nodes[n]['label']}" for n in comp
                                                if g.nodes[n]["kind"] != "domain"})[:10]})
        for n in comp:
            d = g.nodes[n]
            nodes.append({"id": n, "label": d["label"], "kind": d["kind"], "score": d.get("score"), "fraud": d.get("fraud", False),
                          "scan_id": d.get("scan_id")})
    for a, b, d in g.edges(data=True):
        edges.append({"from": a, "to": b, "kind": d["kind"]})
    campaigns.sort(key=lambda c: -len(c["domains"]))
    return {"nodes": nodes, "edges": edges, "campaigns": campaigns[:20],
            "note": "Shared infrastructure is an investigative lead, not proof of fraud. Common providers "
                    "(Cloudflare anycast IPs, large DNS hosts) are excluded."}
