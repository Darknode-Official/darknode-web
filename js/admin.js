// Account Settings (owner-only). Scaffold stub - built in the ultraplan pass.
// All actions here are ALSO enforced server-side by the Security Rules, so this
// module only needs to build the UI and call Firestore.
//
// Responsibilities:
//   - Whitelist manager: list users (status), add/remove Gmails (single + bulk paste).
//       add    -> set users/{uid}.status = 'allowed'  (owner-only per rules)
//       remove -> set status back to 'pending' / delete
//   - Announcements: create / edit / delete docs in announcements (shown to everyone).
//   - "Log out everyone but me": increment settings/session_epoch.value; every other
//       client's epoch watcher then signs them out. (Hard token revocation would need
//       an optional Firebase Cloud Function using the Admin SDK.)
//   - Access requests: review + approve items in access_requests.
console.log("[sentinel] admin module loaded");
