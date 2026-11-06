# ADR-0001: Upload `.eml` files before building an inbound mailbox

**Status:** Accepted
**Date:** 2026-11-06

## Context

Ideally, staff would forward suspicious emails to an address like `phish@company.example` and reports would arrive automatically. On AWS that means SES email receiving, which needs a domain I control, MX records pointing at SES, and a region that supports inbound email. All of that is setup work that teaches me little about the core problem.

## Decision

For the first version, staff submit the suspicious email as a `.eml` file through an authenticated upload. Most mail clients can save a message as `.eml`. The rest of the pipeline is the same whichever way the report arrives, because both paths end with a raw email object in S3.

## Consequences

- The triage pipeline can be built and demoed without buying or configuring a domain.
- Reporting takes one more step for staff than forwarding would.
- SES inbound can be added later as a second entry point writing to the same bucket prefix, with no change to the triage Lambda. That's a natural extension to talk about.
