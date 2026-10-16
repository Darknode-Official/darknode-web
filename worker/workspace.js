// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Workspace membership — server side (Phase B2). The direct generalization of VAULT's
// memberRole (worker/vault.js): the caller's role in a team workspace is read from
// Firestore (workspaces/{wid}/members/{uid}) with the caller's OWN ID token, so Firestore
// rules decide what that read returns and only a workspace owner/admin can write a member
// doc. A client can never grant itself a role.
//
// One workspace id is special: a user's PERSONAL workspace, whose id is their own uid.
// They are its implicit owner and it has no member doc — this is the Phase B1 personal
// graph, so personal cloud sync keeps working with zero migration. Every other workspace
// id is a team workspace and requires a real member doc.

import { ROLES, canDo, isPersonalWorkspace } from "../public/js/core/workspace-roles.js";

export { ROLES, canDo, isPersonalWorkspace };

// A workspace id is a Firebase uid (personal) or a generated team id (same shape as a
// vault id so the two id spaces never collide with a uid by accident).
export const WORKSPACE_ID = /^[A-Za-z0-9_-]{1,128}$/;
export const TEAM_WORKSPACE_ID = /^[A-Za-z0-9_-]{8,40}$/;

// Read workspaces/{wid}/members/{uid} with the caller's token. Returns a role string from
// ROLES (never "removed" — a removed member is treated as not a member) or null.
export async function workspaceMemberRole(projectId, wid, uid, token, fetchImpl = fetch) {
  const url = "https://firestore.googleapis.com/v1/projects/" + projectId +
    "/databases/(default)/documents/workspaces/" + encodeURIComponent(wid) + "/members/" + encodeURIComponent(uid);
  const r = await fetchImpl(url, { headers: { Authorization: "Bearer " + token } });
  if (r.status === 404 || r.status === 403) return null;
  if (!r.ok) throw new Error("membership lookup failed (" + r.status + ")");
  const d = await r.json();
  const f = (d && d.fields) || {};
  if (!f.uid || f.uid.stringValue !== uid) return null;
  const role = f.role && f.role.stringValue;
  if (!ROLES.includes(role) || role === "removed") return null;
  return role;
}

// Resolve the caller's effective role for a workspace, honouring the personal fast path.
// `token` is the caller's verified ID token (for the Firestore read on team workspaces).
export async function resolveWorkspaceRole(projectId, wid, uid, token, fetchImpl = fetch) {
  if (isPersonalWorkspace(wid, uid)) return "owner"; // your own private workspace
  return workspaceMemberRole(projectId, wid, uid, token, fetchImpl);
}
