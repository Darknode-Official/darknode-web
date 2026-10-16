// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Workspace (team) roles — the non-financial generalization of vault/roles.js. A
// workspace is a shared security context: its security graph (Phase B1), and later its
// cases, findings and incidents (B3), are visible to its members. These roles say what a
// member may do; the worker (worker/workspace.js + worker/graph.js) ENFORCES them, and
// the browser UI only uses them to hide actions that would fail.
//
// Unlike VAULT's money roles (initiator/approver/auditor), security operations split by
// what people actually do: analysts investigate and enrich, responders act on incidents.
// Both write the graph; the distinction scopes case/incident ownership in B3.

export const ROLES = ["owner", "admin", "analyst", "responder", "viewer", "removed"];

// A role still counted as being on the team (everything except the tombstone "removed").
export const ACTIVE_ROLES = ROLES.filter((r) => r !== "removed");

export const CAN = {
  read: ["owner", "admin", "analyst", "responder", "viewer"], // see the shared graph
  write: ["owner", "admin", "analyst", "responder"],           // add/change graph entities
  manageMembers: ["owner", "admin"],                           // invite / change roles
  rename: ["owner", "admin"],                                  // rename the workspace
  delete: ["owner"],                                           // (reserved) retire a workspace
  setRole: ["owner"],                                          // only an owner mints owners/admins
};

export const canDo = (role, op) => !!(CAN[op] && CAN[op].includes(role));

export const ROLE_HELP = {
  owner: "Full control: members, roles, rename, and everything an analyst can do. Cannot change their own role.",
  admin: "Invites members and sets non-owner roles; full read/write on the graph.",
  analyst: "Investigates and enriches: adds and edits entities and relationships in the shared graph.",
  responder: "Acts on incidents: full read/write on the graph, scoped to response work in B3.",
  viewer: "Read-only across the shared graph.",
};

export const ROLE_LABEL = { owner: "Owner", admin: "Admin", analyst: "Analyst", responder: "Responder", viewer: "Viewer", removed: "Removed" };

// Is this id a user's personal workspace? A personal workspace id is the user's own uid:
// they are its implicit owner and it needs no member doc (this is the Phase B1 graph).
export const isPersonalWorkspace = (wid, uid) => !!wid && wid === uid;
