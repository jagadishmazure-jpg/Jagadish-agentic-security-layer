"""Thin Streamlit demo for the agentic security layer (lazy import)."""

try:
    import streamlit as st
except ImportError:  # pragma: no cover
    raise SystemExit("streamlit is not installed; demo only") from None

from agelayer import demo_helpers


def main():
    st.title("Agentic Security Layer — demo")
    out = demo_helpers.run_scenario()

    st.subheader("Shadow findings")
    for f in out["shadow_findings"]:
        st.write(f"{f['caller_id']}: score {f['privilege_score']} -> "
                 f"{f['recommendation']} ({f['recommendation_rule']})")

    st.subheader("Blast radius (agt-deployer)")
    st.write(f"{out['blast_radius_nodes']} reachable nodes, "
             f"{out['escalation_paths']} escalation paths, "
             f"{out['compromise_exposed']} exposed on compromise")

    st.subheader("Bridge decisions")
    for d in out["bridge_decisions"]:
        st.write(f"{d['agent_id']} -> {d['tool']}: {d['decision']} "
                 f"({d.get('policy_id')})")

    st.subheader("Zero-standing-privilege posture")
    st.write(f"score: {out['zsp_score']}/100")
    for imp in out["zsp_improvements"]:
        st.write(f"P{imp['priority']}: {imp['area']} — {imp['detail']}")

    st.write(f"audit chain valid: {out['audit_valid']} "
             f"({out['audit_entries']} entries)")


if __name__ == "__main__":
    main()
