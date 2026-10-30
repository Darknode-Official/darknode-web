// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// VAULT team roles: what each role may do. Shared by the worker (worker/vault.js), which
// ENFORCES it, and the browser UI, which only uses it to hide buttons that would fail.

export const ROLES = ["owner", "admin", "initiator", "approver", "auditor", "viewer"];

export const CAN = {
  init: ["owner"],
  openAccount: ["owner", "admin"],
  post: ["owner"],
  setPolicy: ["owner"],
  createTransfer: ["owner", "admin", "initiator"],
  approve: ["owner", "admin", "approver"],
  reject: ["owner", "admin", "approver"],
  release: ["owner", "admin", "approver"],
  reconcile: ["owner", "admin"],
};
// Own keys only: an op named "constructor" or "toString" must be a 403, not a TypeError.
export const canDo = (role, op) => Object.prototype.hasOwnProperty.call(CAN, op) && CAN[op].includes(role);

export const ROLE_HELP = {
  owner: "Everything, including members, approval policy and opening entries. Cannot change their own role.",
  admin: "Opens accounts, creates, approves and releases movements, reconciles statements.",
  initiator: "Creates fund movements. Cannot approve or release them.",
  approver: "Approves, rejects and releases movements created by someone else.",
  auditor: "Read-only, including the full audit chain and verification.",
  viewer: "Read-only balances and movements.",
};
