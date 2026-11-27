# Improvement: recoverable first adoption under a bootstrap task

## Intent

A first `mise bootstrap --adopt` invoked by another bootstrap's task must apply the incoming files under its own active recovery operation.

## Evidence and ownership

- `OperationScope::begin_with_wait` treated an inherited `__MISE_HISTORY_OPERATION` as sufficient to make every nested scope inactive.
- An unenrolled outer bootstrap exports that id while its journal and operation lock are still deferred. The id is not evidence that any process owns recovery.
- `Applying::check_planning_still_holds` correctly refuses an inactive scope before writing files. Keep that invariant.
- Ordinary Bootstrap/Capture nesting continues to attach to the parent. Apply owns its recovery writer and must acquire the existing operation lock. A parent that actually holds the lock still prevents application.
- The child restores the inherited id when it closes its own scope; it cannot erase its caller's attachment context.

## Contract and proofs

`mise run test:history:cold-adoption` covers the actual incoming-application consumer: a fresh store, an enrolled incoming file, an inherited lazy-parent id, ancestry adoption, a completed Apply operation with its upstream and affected path, and restoration of the parent id. It also covers rejection when an active parent holds the operation lock. `mise run test:history` is the regression gate. No new recovery API or bypass is introduced.

The separate Linux end-to-end proof is the real remote bootstrap task invoking `mise bootstrap --adopt` on a fresh disposable guest; it must write the enrolled files, not merely pass a model test.
