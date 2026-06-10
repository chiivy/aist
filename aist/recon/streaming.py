"""
AIST Streaming Response Handler

Handles both streaming and non-streaming agent
responses so the rest of AIST does not need
to handle both cases separately.

Assembles complete responses from streamed
chunks and strips metadata tokens before
passing content to the evidence collector.
"""
