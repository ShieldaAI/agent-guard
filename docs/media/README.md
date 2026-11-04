# Tool permission demonstration

The GIF and terminal cast are annotated replays of verified output from
`node examples/tool-permissions.mjs` using the published
`@shieldaai/agent-guard@0.1.0-alpha.2` package. Pauses were added for explanation;
the sixty-four-second replay is not a real-time recording of command execution.

The example asserts handler counts for an ungranted resource, missing approval,
one approved action and rejected replay. It uses synthetic data without a model
API key or external side effects. Run the
[walkthrough](../guides/tool-permissions.md) to reproduce it.

- [Animated demonstration](tool-permissions.gif)
- [Static poster](tool-permissions-poster.png)
- [Asciinema v2 terminal replay](tool-permissions.cast)
