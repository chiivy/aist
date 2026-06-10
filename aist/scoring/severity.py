"""
AIST Severity Scoring

Calculates contextual vulnerability severity
based on the finding type and the capabilities
of the agent under test.

The same finding scores differently depending
on what the agent can access and do.
An agent with access to email, files, and
databases presents a different risk profile
than one with no tool access.
"""
