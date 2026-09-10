import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      /**
       * `react-hooks/set-state-in-effect` — kept as a warning, not an error.
       *
       * It is a React Compiler PERFORMANCE recommendation (one extra render
       * pass), not a correctness rule, and every occurrence in this codebase
       * was reviewed individually. They fall into three groups, none of them
       * defects:
       *
       *  1. The hydration guards — `useEffect(() => setMounted(true), [])` and
       *     the `nowMs` clocks on the dashboard and 0-day pages. These exist
       *     specifically to STOP a real bug: reading `Date.now()` during render
       *     made the server-rendered HTML disagree with the client's first
       *     paint, which React reports as a hydration mismatch. A component
       *     cannot know it has mounted without one render, so this pattern is
       *     inherent, and it is what React's own documentation prescribes.
       *
       *  2. Fetch-on-mount — `setLoading(true)` before an effect's request.
       *     Initialising the state to `true` instead is not equivalent here,
       *     because these effects return early when they have nothing to fetch
       *     and would otherwise show a spinner forever.
       *
       *  3. Prop-to-state sync in dialogs, resetting the active tab or the page
       *     number when the subject changes.
       *
       * Left as a warning so new instances stay visible and get the same
       * scrutiny, rather than disabled outright.
       */
      "react-hooks/set-state-in-effect": "warn",
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
