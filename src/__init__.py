"""InsideJob - an offline audit of what LLM-agent policy enforcers admit.

The matcher of a policy engine (Progent, Janus) is compared against a sound
reference matcher; every disagreement is a labelled enforcement gap. AgentDojo
and Progent are vendored unmodified (see VENDOR.md).
"""
