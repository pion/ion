# Ion - A Community-Driven SFU

## What is Ion?

Ion began as the official Selective Forwarding Unit (SFU) for the Pion WebRTC project. It quickly gathered an enthusiastic community but eventually grew too much that it had to move out of the Pion org: [Ion grown up and moving out](https://pion.ly/blog/ion-grown-up-and-moving-out/).

Maintenance slowed as core contributors moved on and the user base split between Pion and Ion. This repository aims to reboot the project and bring it back under Pion's active community.

## Why are we restarting Ion?

The Pion ecosystem lacks a fully-featured, community-maintained application that showcases and validates the core libraries. A healthy SFU implementation helps to:

* Surface bugs and missing features in Pion itself.
* Provide a reference architecture for developers building on top of Pion.
* Strengthen the open-source WebRTC and Go landscape.

## Project Goals

1. Deliver an SFU with feature-parity to modern commercial offerings.
   * For example: First-class support for SVC, simulcast, and multicasting a single stream to multiple rooms from a single source.
2. Be cloud-native by design.
   * Simple, horizontally-scalable architecture.
   * Multiple SFU instances can serve the same room concurrently.
3. Offer a modern, layered API.
   * High-level plugin/extension API that hides WebRTC details.
   * Low-level API for advanced use-cases, users should be able to re-implement the same features in the high-level API and provide their own interfaces, This should be abstracted away from non power users.
4. Provide a clean, typed Web SDK.
5. Ship a reference web application with a modern UI.
6. Supply an SDK for embedded / IoT devices (Minimum spec requirements will be evaluated in the future, and direct hardware acceleration will be evaluated), Using Pion compiled with tinygo, This will require finishing the tinygo support in Pion.
7. Include WHIP/WHEP support from day one.

## Pain Points with the Current Pion-Based Stack

1. RTX/FEC handling is opaque. An SFU cannot easily strip, regenerate, or adapt redundancy streams—especially in multi-rendition, multicasting, or SVC scenarios.
2. Transport state is tightly coupled to in-memory stateful objects, preventing seamless migration of streams between SFU instances (UDP, DTLS, SRTP, SCTP etc), For security reasons, this will not include the TLS state, Will require finishing the DTLS restart (which should be even simpler with DTLS 1.3).
3. Limited support for modern codecs features.
4. Incomplete statistics and congestion-control APIs.
5. Security hardening (DTLS/SRTP cipher suites, DTLS 1.3, rate limiting, quota management) is missing.
6. Monitoring and observability hooks (Prometheus, OpenTelemetry, tracing) are hard to implement, because many API and states are private.

## Contributing

We welcome issues, discussions, and pull requests. See `CONTRIBUTING.md` for guidelines (coming soon).

## Stage 0 - Next Steps

The project is currently in **Stage 0: Discovery & Design**. Our immediate focus is to build consensus on the initial architecture and governance model.

1. **Gather feedback** - Open GitHub issues or start a Discussion in the [discord](https://discord.gg/PngbdqpFbt) to share pain points, feature requests, and use-cases in the #ion channel.
2. **Draft design proposals (RFCs)** - Contributors submit markdown documents in describing architecture ideas, APIs, and migration strategies.
3. **Community voting** - RFCs will be discussed on Discord and in GitHub Discussions. We will use 👍/👎 reactions to measure support and move proposals forward.
4. **Define the MVP** - Based on accepted RFCs, we will lock a minimal feature set for the first public milestone.
5. **Decide on the name** - We will decide on the name of the project, if we'll keep the name "Ion" and pick a new major version or pick a new name to avoid confusion with the original Ion project.

Our goal is to complete Stage 0 hopefully under **4 weeks** and transition into implementation (Stage 1).

Feel free to make commits / PRs to update this README.md.
