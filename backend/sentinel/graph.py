"""Access graph and attack-path enumeration for an identity's credentials."""

from __future__ import annotations

from datetime import datetime

from .iam import IamState, statement_allows
from .models import AttackPath, Graph, GraphEdge, GraphNode

PROBE_SESSION = "ASIAPROBEFRESHSESSN0"


def _short(key: str) -> str:
    return f"{key[:4]}…{key[-4:]}"


def identity_credentials(state: IamState, user: str, now: datetime) -> list[tuple[str, str]]:
    """(key_id, kind) for the user's access keys and live sessions they minted."""
    creds = [(k["id"], "key") for k in state.users[user]["access_keys"]]
    for sk, s in state.d["sessions"].items():
        if s.get("origin_user") == user and sk != PROBE_SESSION:
            creds.append((sk, "session"))
    return creds


def _assumable_roles(state: IamState, user: str) -> list[str]:
    arn = state.users[user]["arn"]
    return [r for r, role in state.roles.items() if arn in role.get("trust", {}).get("AWS", [])]


def attack_paths(state: IamState, user: str, compromised: set[str], now: datetime) -> list[AttackPath]:
    paths: list[AttackPath] = []
    targets = [r for r in state.resources if r["critical"]]
    for key_id, kind in identity_credentials(state, user, now):
        for res in targets:
            action, probe = res["probe"]["action"], res["probe"]["resource"]
            if kind == "key":
                d = state.evaluate(key_id, action, probe, now)
                if d.allowed:
                    paths.append(AttackPath(credential=key_id, target=res["arn"], target_name=res["name"],
                                            permission=action, compromised_credential=key_id in compromised,
                                            nodes=[key_id, f"user:{user}", f"policy:user:{user}:{d.policy}",
                                                   res["arn"]]))
                for role in _assumable_roles(state, user):
                    sim = state.clone()
                    ar = sim.assume_role(key_id, role, now, PROBE_SESSION)
                    if not ar.allowed:
                        continue
                    d2 = sim.evaluate(PROBE_SESSION, action, probe, now)
                    if d2.allowed:
                        paths.append(AttackPath(
                            credential=key_id, target=res["arn"], target_name=res["name"], permission=action,
                            compromised_credential=key_id in compromised,
                            nodes=[key_id, f"user:{user}", f"policy:user:{user}:{ar.policy}", f"role:{role}",
                                   f"policy:role:{role}:{d2.policy}", res["arn"]]))
            else:
                d = state.evaluate(key_id, action, probe, now)
                if d.allowed:
                    role = state.d["sessions"][key_id]["role"]
                    paths.append(AttackPath(credential=key_id, target=res["arn"], target_name=res["name"],
                                            permission=action, compromised_credential=key_id in compromised,
                                            nodes=[key_id, f"role:{role}", f"policy:role:{role}:{d.policy}",
                                                   res["arn"]]))
    return paths


def build_graph(state: IamState, user: str, compromised: set[str], now: datetime) -> Graph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}

    def edge(s: str, t: str, label: str) -> None:
        eid = f"{s}->{t}:{label}"
        edges[eid] = GraphEdge(id=eid, source=s, target=t, label=label)

    nodes[f"user:{user}"] = GraphNode(id=f"user:{user}", label=user, kind="user", layer=1, detail="IAM user")
    roles = _assumable_roles(state, user)
    for key_id, kind in identity_credentials(state, user, now):
        auth = state.authenticate(key_id, now)
        live = not isinstance(auth, str)
        if live and kind == "session":
            live = not state.evaluate(key_id, "s3:GetObject", "arn:aws:s3:::build-artifacts/probe",
                                      now).reason.startswith("explicit deny")
        label = ("session " if kind == "session" else "key ") + _short(key_id)
        nodes[key_id] = GraphNode(id=key_id, label=label, kind="credential", layer=0,
                                  compromised=key_id in compromised, disabled=not live,
                                  detail="STS session" if kind == "session" else "long-lived access key")
        if live:
            if kind == "key":
                edge(key_id, f"user:{user}", "authenticates")
            else:
                edge(key_id, f"role:{state.d['sessions'][key_id]['role']}", "session of")

    for owner_kind, owner, layer in [("user", user, 2)] + [("role", r, 4) for r in roles]:
        owner_id = f"{owner_kind}:{owner}"
        if owner_kind == "role":
            nodes[owner_id] = GraphNode(id=owner_id, label=owner, kind="role", layer=3, detail="IAM role")
        for pname, doc in state.policies(owner_kind, owner).items():
            pid = f"policy:{owner_kind}:{owner}:{pname}"
            nodes[pid] = GraphNode(id=pid, label=pname, kind="policy", layer=layer, detail="inline policy")
            edge(owner_id, pid, "has policy")
            if owner_kind == "user":
                for r in roles:
                    if statement_allows(doc, "sts:AssumeRole", state.roles[r]["arn"]):
                        edge(pid, f"role:{r}", "sts:AssumeRole")
            for res in state.resources:
                if statement_allows(doc, res["probe"]["action"], res["probe"]["resource"]):
                    nodes.setdefault(res["arn"], GraphNode(id=res["arn"], label=res["name"], kind="resource",
                                                           layer=5, critical=res["critical"],
                                                           detail=res.get("description", "")))
                    edge(pid, res["arn"], res["probe"]["action"])
    for res in state.resources:
        if res["critical"]:
            nodes.setdefault(res["arn"], GraphNode(id=res["arn"], label=res["name"], kind="resource", layer=5,
                                                   critical=True, detail=res.get("description", "")))
    return Graph(nodes=list(nodes.values()), edges=list(edges.values()))


def diff_graph(before: Graph, after: Graph) -> Graph:
    """Overlay the post-remediation graph on the original: removed edges are kept and marked blocked."""
    after_nodes = {n.id: n for n in after.nodes}
    nodes = []
    for n in before.nodes:
        nodes.append(after_nodes.pop(n.id, n.model_copy(update={"disabled": True})))
    nodes += list(after_nodes.values())
    after_edges = {e.id for e in after.edges}
    edges = [e if e.id in after_edges else e.model_copy(update={"blocked": True}) for e in before.edges]
    edges += [e for e in after.edges if e.id not in {b.id for b in before.edges}]
    return Graph(nodes=nodes, edges=edges)
