# Deploying account-tree isolation

This opt-in feature restricts candidates selected through CPA's standard scheduler
plugin API. It is not a complete isolation boundary: plugin-owned executors and
other paths that bypass the scheduler are outside its coverage. Client ancestry
metadata is not authenticated proof of parentage.

1. Build and test the plugin for the host platform using the README commands.
2. Back up the current library, configuration and state. Keep credentials private.
3. Classify each credential by exact ID, provider, scope and source using the
   sanitized example. Preserve downstream key bindings and native model aliases.
4. Initialize state only for a new installation. Existing state must be retained;
   removing it forgets the scope of resumed tasks.
5. Enable account isolation and select this plugin as the scheduler. Confirm
   registration, then exercise an allowed root, child and resumed session and
   denied cross-scope routes. Verify denial caused no upstream request.

Repeat those checks after a core or plugin update. If registration fails, stop
scoped traffic and restore the compatible library/configuration; the host can fall
back to its own scheduler when this plugin is unavailable or disabled.

A stale lock, corrupt store or capacity limit denies selection. Recover from a
verified backup instead of resetting a live store. HTTP rejection status is owned
by CPA; current scheduler errors can surface as HTTP 500.
