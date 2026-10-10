/**
 * ┌─ THE ONE LINE THAT MOVES WHEN THE BARREL IS UPDATED ─────────────────────┐
 * │ `shared/src/index.ts` is the barrel: a feature may add a module to        │
 * │ `@obliwan/shared` but not a re-export to its barrel. So the logs contract │
 * │ (`shared/src/logs.ts`) is reached here through the package's subpath, and │
 * │ every server file that needs it imports from THIS module instead of       │
 * │ scattering `@obliwan/shared/dist/logs` across a dozen files.              │
 * │                                                                          │
 * │ When `export * from './logs';` lands in the barrel, this file becomes     │
 * │     export * from '@obliwan/shared';                                      │
 * │ or disappears entirely and the imports move to `@obliwan/shared`. One     │
 * │ edit either way, in one place — which is the whole reason it exists       │
 * │ rather than the import being repeated.                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export * from '@obliwan/shared/dist/logs';
