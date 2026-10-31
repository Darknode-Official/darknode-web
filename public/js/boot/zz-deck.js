// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Moved out of index.html so the page runs under a CSP without 'unsafe-inline'.
import { renderDeck } from "/js/deck-ui.js?v=sec12";
import * as nav from "/js/console-nav.js?v=20261013k";
const tier = new URLSearchParams(location.search).get("tier") || "enterprise";
renderDeck(document.body, {isOwner:false, tier, groups:(nav.NAV||[]).map(g=>({id:g.id,name:g.name,color:g.color,items:g.items||[]})), user:{displayName:"Test", email:"test@darknode.ai"}, onSignOut(){}});
