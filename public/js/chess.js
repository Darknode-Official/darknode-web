// Darknode Chess — play against Stockfish in the browser.
// Self-contained: full chess rules, SVG pieces, drag+click movement, Stockfish WASM engine.

const PIECE_CHARS = { K: "♔", Q: "♕", R: "♖", B: "♗", N: "♘", P: "♙", k: "♚", q: "♛", r: "♜", b: "♝", n: "♞", p: "♟" };
const FILES = "abcdefgh";
const RANKS = "87654321";

const PIECE_SVG = {
  K: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22.5 11.63V6M20 8h5" stroke-linejoin="miter"/><path d="M22.5 25s4.5-7.5 3-10.5c0 0-1-2.5-3-2.5s-3 2.5-3 2.5c-1.5 3 3 10.5 3 10.5" fill="#fff" stroke-linecap="butt" stroke-linejoin="miter"/><path d="M11.5 37c5.5 3.5 15.5 3.5 21 0v-7s9-4.5 6-10.5c-4-6.5-13.5-3.5-16 4V27v-3.5c-3.5-7.5-13-10.5-16-4-3 6 5 10 5 10V37z" fill="#fff"/><path d="M11.5 30c5.5-3 15.5-3 21 0M11.5 33.5c5.5-3 15.5-3 21 0M11.5 37c5.5-3 15.5-3 21 0"/></g></svg>`,
  Q: `<svg viewBox="0 0 45 45"><g fill="#fff" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 12a2 2 0 1 1-4 0 2 2 0 1 1 4 0zM24.5 7.5a2 2 0 1 1-4 0 2 2 0 1 1 4 0zM41 12a2 2 0 1 1-4 0 2 2 0 1 1 4 0zM16 8.5a2 2 0 1 1-4 0 2 2 0 1 1 4 0zM33 9a2 2 0 1 1-4 0 2 2 0 1 1 4 0z"/><path d="M9 26c8.5-1.5 21-1.5 27 0l2-12-7 11V11l-5.5 13.5-3-15-3 15L14 11v14L7 14l2 12z" stroke-linecap="butt"/><path d="M9 26c0 2 1.5 2 2.5 4 1 1.5 1 1 .5 3.5-1.5 1-1.5 2.5-1.5 2.5-1.5 1.5.5 2.5.5 2.5 6.5 1 16.5 1 23 0 0 0 1.5-1 0-2.5 0 0 .5-1.5-1-2.5-.5-2.5-.5-2 .5-3.5 1-2 2.5-2 2.5-4-8.5-1.5-18.5-1.5-27 0z" stroke-linecap="butt"/><path d="M11.5 30c3.5-1 18.5-1 22 0M12 33.5c6-1 15-1 21 0" fill="none"/></g></svg>`,
  R: `<svg viewBox="0 0 45 45"><g fill="#fff" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 39h27v-3H9v3zM12 36v-4h21v4H12zM11 14V9h4v2h5V9h5v2h5V9h4v5" stroke-linecap="butt"/><path d="M34 14l-3 3H14l-3-3"/><path d="M15 17v7h15v-7" stroke-linecap="butt" stroke-linejoin="miter"/><path d="M14 29.5v-13h17v13H14z" stroke-linecap="butt" stroke-linejoin="miter"/><path d="M14 29.5L11 36h23l-3-6.5H14z" stroke-linecap="butt" stroke-linejoin="miter"/></g></svg>`,
  B: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><g fill="#fff" stroke-linecap="butt"><path d="M9 36c3.39-.97 10.11.43 13.5-2 3.39 2.43 10.11 1.03 13.5 2 0 0 1.65.54 3 2-.68.97-1.65.99-3 .5-3.39-.97-10.11.46-13.5-1-3.39 1.46-10.11.03-13.5 1-1.354.49-2.323.47-3-.5 1.354-1.94 3-2 3-2z"/><path d="M15 32c2.5 2.5 12.5 2.5 15 0 .5-1.5 0-2 0-2 0-2.5-2.5-4-2.5-4 5.5-1.5 6-11.5-5-15.5-11 4-10.5 14-5 15.5 0 0-2.5 1.5-2.5 4 0 0-.5.5 0 2z"/><path d="M25 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 1 1 5 0z"/></g><path d="M17.5 26h10M15 30h15M22.5 15.5v5M20 18h5" stroke-linejoin="miter"/></g></svg>`,
  N: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10c10.5 1 16.5 8 16 29H15c0-9 10-6.5 8-21" fill="#fff"/><path d="M24 18c.38 2.91-5.55 7.37-8 9-3 2-2.82 4.34-5 4-1.042-.94 1.41-3.04 0-3-1 0 .19 1.23-1 2-1 0-4.003 1-4-4 0-2 6-12 6-12s1.89-1.9 2-3.5c-.73-.994-.5-2-.5-3 1-1 3 2.5 3 2.5h2s.78-1.992 2.5-3c1 0 1 3 1 3" fill="#fff"/><path d="M9.5 25.5a.5.5 0 1 1-1 0 .5.5 0 1 1 1 0zM14.933 15.75a.5 1.5 30 1 1-.866-.5.5 1.5 30 1 1 .866.5z" fill="#000"/></g></svg>`,
  P: `<svg viewBox="0 0 45 45"><path d="M22.5 9c-2.21 0-4 1.79-4 4 0 .89.29 1.71.78 2.38C17.33 16.5 16 18.59 16 21c0 2.03.94 3.84 2.41 5.03C15.41 27.09 11 31.58 11 39.5H34c0-7.92-4.41-12.41-7.41-13.47C28.06 24.84 29 23.03 29 21c0-2.41-1.33-4.5-3.28-5.62.49-.67.78-1.49.78-2.38 0-2.21-1.79-4-4-4z" fill="#fff" stroke="#000" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  k: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22.5 11.63V6" stroke-linejoin="miter"/><path d="M22.5 25s4.5-7.5 3-10.5c0 0-1-2.5-3-2.5s-3 2.5-3 2.5c-1.5 3 3 10.5 3 10.5" fill="#000" stroke-linecap="butt" stroke-linejoin="miter"/><path d="M11.5 37c5.5 3.5 15.5 3.5 21 0v-7s9-4.5 6-10.5c-4-6.5-13.5-3.5-16 4V27v-3.5c-3.5-7.5-13-10.5-16-4-3 6 5 10 5 10V37z" fill="#000"/><path d="M20 8h5" stroke-linejoin="miter"/><path d="M11.5 30c5.5-3 15.5-3 21 0" stroke="#fff"/><path d="M11.5 33.5c5.5-3 15.5-3 21 0" stroke="#fff"/><path d="M11.5 37c5.5-3 15.5-3 21 0" stroke="#fff"/></g></svg>`,
  q: `<svg viewBox="0 0 45 45"><g fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><g fill="#000" stroke="none"><circle cx="6" cy="12" r="2.75"/><circle cx="14" cy="9" r="2.75"/><circle cx="22.5" cy="8" r="2.75"/><circle cx="31" cy="9" r="2.75"/><circle cx="39" cy="12" r="2.75"/></g><path d="M9 26c8.5-1.5 21-1.5 27 0l2.5-12.5L31 25l-.3-14.1-5.2 13.6-3-14.5-3 14.5L14 11 14 25 6.5 13.5 9 26z" fill="#000" stroke-linecap="butt"/><path d="M9 26c0 2 1.5 2 2.5 4 1 1.5 1 1 .5 3.5-1.5 1-1.5 2.5-1.5 2.5-1.5 1.5.5 2.5.5 2.5 6.5 1 16.5 1 23 0 0 0 1.5-1 0-2.5 0 0 .5-1.5-1-2.5-.5-2.5-.5-2 .5-3.5 1-2 2.5-2 2.5-4-8.5-1.5-18.5-1.5-27 0z" fill="#000" stroke-linecap="butt"/><path d="M11 38.5a35 35 1 0 0 23 0" fill="none" stroke-linecap="butt"/><path d="M11 29a35 35 1 0 1 23 0" fill="none" stroke="#fff" stroke-linecap="butt"/><path d="M12.5 31.5h20" fill="none" stroke="#fff" stroke-linejoin="miter"/><path d="M11.5 34.5a35 35 1 0 0 22 0" fill="none" stroke="#fff"/><circle cx="6" cy="12" r="2" fill="#000"/><circle cx="14" cy="9" r="2" fill="#000"/><circle cx="22.5" cy="8" r="2" fill="#000"/><circle cx="31" cy="9" r="2" fill="#000"/><circle cx="39" cy="12" r="2" fill="#000"/></g></svg>`,
  r: `<svg viewBox="0 0 45 45"><g fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 39h27v-3H9v3zM12.5 32l1.5-2.5h17l1.5 2.5h-20zM12 36v-4h21v4H12z" stroke-linecap="butt"/><path d="M14 29.5v-13h17v13H14z" stroke-linecap="butt" stroke-linejoin="miter"/><path d="M14 16.5L11 14h23l-3 2.5H14zM11 14V9h4v2h5V9h5v2h5V9h4v5H11z" stroke-linecap="butt"/><path d="M12 35.5h21M13 31.5h19M14 29.5h17M14 16.5h17M11 14h23" fill="none" stroke="#fff" stroke-width="1" stroke-linejoin="miter"/></g></svg>`,
  b: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><g fill="#000" stroke-linecap="butt"><path d="M9 36c3.39-.97 10.11.43 13.5-2 3.39 2.43 10.11 1.03 13.5 2 0 0 1.65.54 3 2-.68.97-1.65.99-3 .5-3.39-.97-10.11.46-13.5-1-3.39 1.46-10.11.03-13.5 1-1.354.49-2.323.47-3-.5 1.354-1.94 3-2 3-2z"/><path d="M15 32c2.5 2.5 12.5 2.5 15 0 .5-1.5 0-2 0-2 0-2.5-2.5-4-2.5-4 5.5-1.5 6-11.5-5-15.5-11 4-10.5 14-5 15.5 0 0-2.5 1.5-2.5 4 0 0-.5.5 0 2z"/><path d="M25 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 1 1 5 0z"/></g><path d="M17.5 26h10M15 30h15M22.5 15.5v5M20 18h5" stroke="#fff" stroke-linejoin="miter"/></g></svg>`,
  n: `<svg viewBox="0 0 45 45"><g fill="none" fill-rule="evenodd" stroke="#000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10c10.5 1 16.5 8 16 29H15c0-9 10-6.5 8-21" fill="#000"/><path d="M24 18c.38 2.91-5.55 7.37-8 9-3 2-2.82 4.34-5 4-1.042-.94 1.41-3.04 0-3-1 0 .19 1.23-1 2-1 0-4.003 1-4-4 0-2 6-12 6-12s1.89-1.9 2-3.5c-.73-.994-.5-2-.5-3 1-1 3 2.5 3 2.5h2s.78-1.992 2.5-3c1 0 1 3 1 3" fill="#000"/><path d="M9.5 25.5a.5.5 0 1 1-1 0 .5.5 0 1 1 1 0z" fill="#fff" stroke="#fff"/><path d="M14.933 15.75a.5 1.5 30 1 1-.866-.5.5 1.5 30 1 1 .866.5z" fill="#fff" stroke="#fff"/><path d="M24.55 10.4l-.45 1.45.5.15c3.15 1 5.65 2.49 7.9 6.75S35.75 29.06 35.25 39l-.05.5h2.25l.05-.5c.5-10.06-.88-16.85-3.25-21.34-2.37-4.49-5.79-6.64-9.19-7.16l-.51-.1z" fill="#fff" stroke="none"/></g></svg>`,
  p: `<svg viewBox="0 0 45 45"><path d="M22.5 9c-2.21 0-4 1.79-4 4 0 .89.29 1.71.78 2.38C17.33 16.5 16 18.59 16 21c0 2.03.94 3.84 2.41 5.03C15.41 27.09 11 31.58 11 39.5H34c0-7.92-4.41-12.41-7.41-13.47C28.06 24.84 29 23.03 29 21c0-2.41-1.33-4.5-3.28-5.62.49-.67.78-1.49.78-2.38 0-2.21-1.79-4-4-4z" fill="#000" stroke="#000" stroke-width="1.5" stroke-linecap="round"/></svg>`,
};

// ===== CHESS ENGINE (full rules) =====
function createGame() {
  const INITIAL_FEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1";

  let board = Array(64).fill(null);
  let turn = "w";
  let castling = { K: true, Q: true, k: true, q: true };
  let enPassant = -1;
  let halfmove = 0;
  let fullmove = 1;
  let history = [];

  const rc = (r, c) => r * 8 + c;
  const row = (sq) => sq >> 3;
  const col = (sq) => sq & 7;
  const inBounds = (r, c) => r >= 0 && r < 8 && c >= 0 && c < 8;
  const isWhite = (p) => p && p === p.toUpperCase();
  const isBlack = (p) => p && p === p.toLowerCase();
  const colorOf = (p) => p ? (isWhite(p) ? "w" : "b") : null;
  const enemy = (color) => color === "w" ? "b" : "w";

  function parseFEN(fen) {
    const parts = fen.split(" ");
    board = Array(64).fill(null);
    let sq = 0;
    for (const ch of parts[0]) {
      if (ch === "/") continue;
      if (ch >= "1" && ch <= "8") { sq += +ch; continue; }
      board[sq++] = ch;
    }
    turn = parts[1] || "w";
    castling = { K: false, Q: false, k: false, q: false };
    const cstr = parts[2] || "-";
    if (cstr !== "-") for (const c of cstr) castling[c] = true;
    enPassant = parts[3] && parts[3] !== "-" ? FILES.indexOf(parts[3][0]) + (8 - parseInt(parts[3][1])) * 8 : -1;
    halfmove = parseInt(parts[4]) || 0;
    fullmove = parseInt(parts[5]) || 1;
    history = [];
  }

  function toFEN() {
    let fen = "";
    for (let r = 0; r < 8; r++) {
      let empty = 0;
      for (let c = 0; c < 8; c++) {
        const p = board[rc(r, c)];
        if (p) { if (empty) { fen += empty; empty = 0; } fen += p; }
        else empty++;
      }
      if (empty) fen += empty;
      if (r < 7) fen += "/";
    }
    fen += " " + turn;
    let cstr = "";
    if (castling.K) cstr += "K"; if (castling.Q) cstr += "Q";
    if (castling.k) cstr += "k"; if (castling.q) cstr += "q";
    fen += " " + (cstr || "-");
    fen += " " + (enPassant >= 0 ? FILES[col(enPassant)] + RANKS[row(enPassant)] : "-");
    fen += " " + halfmove + " " + fullmove;
    return fen;
  }

  function pseudoMoves(color, onlyCaptures = false) {
    const moves = [];
    const add = (from, to, flags = 0) => moves.push({ from, to, flags });
    const pawnDir = color === "w" ? -1 : 1;
    const pawnStart = color === "w" ? 6 : 1;
    const promoRank = color === "w" ? 0 : 7;

    for (let sq = 0; sq < 64; sq++) {
      const p = board[sq];
      if (!p || colorOf(p) !== color) continue;
      const r = row(sq), c = col(sq);
      const type = p.toUpperCase();

      if (type === "P") {
        const nr = r + pawnDir;
        if (inBounds(nr, c) && !board[rc(nr, c)] && !onlyCaptures) {
          if (nr === promoRank) { add(sq, rc(nr, c), 4); add(sq, rc(nr, c), 5); add(sq, rc(nr, c), 6); add(sq, rc(nr, c), 7); }
          else {
            add(sq, rc(nr, c));
            if (r === pawnStart && !board[rc(r + 2 * pawnDir, c)]) add(sq, rc(r + 2 * pawnDir, c), 1);
          }
        }
        for (const dc of [-1, 1]) {
          if (!inBounds(nr, c + dc)) continue;
          const target = rc(nr, c + dc);
          if (board[target] && colorOf(board[target]) !== color) {
            if (nr === promoRank) { add(sq, target, 4); add(sq, target, 5); add(sq, target, 6); add(sq, target, 7); }
            else add(sq, target, 2);
          }
          if (target === enPassant) add(sq, target, 3);
        }
      } else {
        const slides = {
          N: [[-2,-1],[-2,1],[-1,-2],[-1,2],[1,-2],[1,2],[2,-1],[2,1]],
          K: [[-1,-1],[-1,0],[-1,1],[0,-1],[0,1],[1,-1],[1,0],[1,1]],
          B: [[-1,-1],[-1,1],[1,-1],[1,1]],
          R: [[-1,0],[1,0],[0,-1],[0,1]],
          Q: [[-1,-1],[-1,0],[-1,1],[0,-1],[0,1],[1,-1],[1,0],[1,1]],
        };
        const dirs = slides[type];
        const sliding = type === "B" || type === "R" || type === "Q";

        for (const [dr, dc] of dirs) {
          let nr = r + dr, nc = c + dc;
          while (inBounds(nr, nc)) {
            const t = board[rc(nr, nc)];
            if (t) {
              if (colorOf(t) !== color) add(sq, rc(nr, nc), 2);
              break;
            }
            if (!onlyCaptures) add(sq, rc(nr, nc));
            if (!sliding) break;
            nr += dr; nc += dc;
          }
        }

        if (type === "K" && !onlyCaptures) {
          if (color === "w") {
            if (castling.K && !board[61] && !board[62] && board[63] === "R") add(sq, 62, 8);
            if (castling.Q && !board[59] && !board[58] && !board[57] && board[56] === "R") add(sq, 58, 9);
          } else {
            if (castling.k && !board[5] && !board[6] && board[7] === "r") add(sq, 6, 8);
            if (castling.q && !board[3] && !board[2] && !board[1] && board[0] === "r") add(sq, 2, 9);
          }
        }
      }
    }
    return moves;
  }

  function isSquareAttacked(sq, byColor) {
    const r = row(sq), c = col(sq);
    const pawnDir = byColor === "w" ? 1 : -1;
    const pawnType = byColor === "w" ? "P" : "p";
    for (const dc of [-1, 1]) {
      const pr = r + pawnDir, pc = c + dc;
      if (inBounds(pr, pc) && board[rc(pr, pc)] === pawnType) return true;
    }
    const knightDirs = [[-2,-1],[-2,1],[-1,-2],[-1,2],[1,-2],[1,2],[2,-1],[2,1]];
    const knightType = byColor === "w" ? "N" : "n";
    for (const [dr, dc] of knightDirs) {
      const nr = r + dr, nc = c + dc;
      if (inBounds(nr, nc) && board[rc(nr, nc)] === knightType) return true;
    }
    const kingType = byColor === "w" ? "K" : "k";
    for (const [dr, dc] of [[-1,-1],[-1,0],[-1,1],[0,-1],[0,1],[1,-1],[1,0],[1,1]]) {
      const nr = r + dr, nc = c + dc;
      if (inBounds(nr, nc) && board[rc(nr, nc)] === kingType) return true;
    }
    const diagTypes = byColor === "w" ? ["B", "Q"] : ["b", "q"];
    for (const [dr, dc] of [[-1,-1],[-1,1],[1,-1],[1,1]]) {
      let nr = r + dr, nc = c + dc;
      while (inBounds(nr, nc)) {
        const t = board[rc(nr, nc)];
        if (t) { if (diagTypes.includes(t)) return true; break; }
        nr += dr; nc += dc;
      }
    }
    const straightTypes = byColor === "w" ? ["R", "Q"] : ["r", "q"];
    for (const [dr, dc] of [[-1,0],[1,0],[0,-1],[0,1]]) {
      let nr = r + dr, nc = c + dc;
      while (inBounds(nr, nc)) {
        const t = board[rc(nr, nc)];
        if (t) { if (straightTypes.includes(t)) return true; break; }
        nr += dr; nc += dc;
      }
    }
    return false;
  }

  function findKing(color) {
    const k = color === "w" ? "K" : "k";
    for (let i = 0; i < 64; i++) if (board[i] === k) return i;
    return -1;
  }

  function inCheck(color) {
    return isSquareAttacked(findKing(color), enemy(color));
  }

  function makeMove(move) {
    const { from, to, flags } = move;
    const piece = board[from];
    const captured = board[to];
    const state = { board: [...board], turn, castling: { ...castling }, enPassant, halfmove, fullmove, captured: null };

    const promoTypes = ["q", "r", "b", "n"];

    board[to] = piece;
    board[from] = null;
    state.captured = captured;

    if (flags === 1) { /* double pawn push */ }
    else if (flags === 3) {
      const epCapSq = rc(row(from), col(to));
      state.captured = board[epCapSq];
      board[epCapSq] = null;
    } else if (flags >= 4 && flags <= 7) {
      const promoChar = promoTypes[flags - 4];
      board[to] = colorOf(piece) === "w" ? promoChar.toUpperCase() : promoChar;
    } else if (flags === 8) {
      if (to === 62) { board[61] = board[63]; board[63] = null; }
      else if (to === 6) { board[5] = board[7]; board[7] = null; }
    } else if (flags === 9) {
      if (to === 58) { board[59] = board[56]; board[56] = null; }
      else if (to === 2) { board[3] = board[0]; board[0] = null; }
    }

    if (flags === 1) enPassant = rc((row(from) + row(to)) / 2, col(from));
    else enPassant = -1;

    if (piece === "K") { castling.K = false; castling.Q = false; }
    if (piece === "k") { castling.k = false; castling.q = false; }
    if (from === 63 || to === 63) castling.K = false;
    if (from === 56 || to === 56) castling.Q = false;
    if (from === 7 || to === 7) castling.k = false;
    if (from === 0 || to === 0) castling.q = false;

    if (piece.toUpperCase() === "P" || captured) halfmove = 0;
    else halfmove++;

    if (turn === "b") fullmove++;
    turn = enemy(turn);

    return state;
  }

  function unmakeMove(state) {
    board = state.board;
    turn = state.turn;
    castling = state.castling;
    enPassant = state.enPassant;
    halfmove = state.halfmove;
    fullmove = state.fullmove;
  }

  function legalMoves(color) {
    const pseudo = pseudoMoves(color || turn);
    const legal = [];
    for (const m of pseudo) {
      if (m.flags === 8 || m.flags === 9) {
        const kingSq = findKing(color || turn);
        if (isSquareAttacked(kingSq, enemy(color || turn))) continue;
        const step = m.to > m.from ? 1 : -1;
        let passThrough = m.from + step;
        if (isSquareAttacked(passThrough, enemy(color || turn))) continue;
        if (m.flags === 9) {
          // queen-side: also check king destination
        }
      }
      const movingColor = color || turn;
      const state = makeMove(m);
      if (!inCheck(movingColor)) {
        legal.push(m);
      }
      unmakeMove(state);
    }
    return legal;
  }

  function toAlgebraic(move, allMoves) {
    const { from, to, flags } = move;
    const piece = board[from];
    const type = piece.toUpperCase();
    const toStr = FILES[col(to)] + RANKS[row(to)];

    if (flags === 8) return "O-O";
    if (flags === 9) return "O-O-O";

    let notation = "";
    if (type === "P") {
      if (col(from) !== col(to)) notation = FILES[col(from)] + "x" + toStr;
      else notation = toStr;
      if (flags >= 4 && flags <= 7) {
        const promoTypes = ["Q", "R", "B", "N"];
        notation += "=" + promoTypes[flags - 4];
      }
    } else {
      notation = type;
      const ambig = (allMoves || []).filter(m =>
        m.to === to && m.from !== from &&
        board[m.from] && board[m.from].toUpperCase() === type &&
        colorOf(board[m.from]) === colorOf(piece)
      );
      if (ambig.length) {
        if (ambig.every(m => col(m.from) !== col(from))) notation += FILES[col(from)];
        else if (ambig.every(m => row(m.from) !== row(from))) notation += RANKS[row(from)];
        else notation += FILES[col(from)] + RANKS[row(from)];
      }
      if (board[to]) notation += "x";
      notation += toStr;
    }

    const state = makeMove(move);
    if (inCheck(turn)) {
      const oppLegal = legalMoves(turn);
      notation += oppLegal.length === 0 ? "#" : "+";
    }
    unmakeMove(state);
    return notation;
  }

  function moveToUCI(move) {
    const promoChars = ["q", "r", "b", "n"];
    let uci = FILES[col(move.from)] + RANKS[row(move.from)] + FILES[col(move.to)] + RANKS[row(move.to)];
    if (move.flags >= 4 && move.flags <= 7) uci += promoChars[move.flags - 4];
    return uci;
  }

  function uciToMove(uci) {
    const fromCol = FILES.indexOf(uci[0]);
    const fromRow = RANKS.indexOf(uci[1]);
    const toCol = FILES.indexOf(uci[2]);
    const toRow = RANKS.indexOf(uci[3]);
    const from = rc(fromRow, fromCol);
    const to = rc(toRow, toCol);
    const promoChar = uci[4];
    const legal = legalMoves();
    return legal.find(m => {
      if (m.from !== from || m.to !== to) return false;
      if (promoChar) {
        const promoChars = ["q", "r", "b", "n"];
        return m.flags >= 4 && m.flags <= 7 && promoChars[m.flags - 4] === promoChar;
      }
      if (m.flags >= 4 && m.flags <= 7) return m.flags === 4;
      return true;
    });
  }

  function gameStatus() {
    const legal = legalMoves();
    const check = inCheck(turn);
    if (legal.length === 0) {
      if (check) return turn === "w" ? "Black wins by checkmate" : "White wins by checkmate";
      return "Draw by stalemate";
    }
    if (halfmove >= 100) return "Draw by 50-move rule";
    if (check) return turn === "w" ? "White is in check" : "Black is in check";
    return "playing";
  }

  function doMove(move) {
    const allMoves = legalMoves();
    const alg = toAlgebraic(move, allMoves);
    const state = makeMove(move);
    history.push({ move, state, alg, uci: moveToUCI(move) });
    return alg;
  }

  function undoMove() {
    if (!history.length) return false;
    const last = history.pop();
    unmakeMove(last.state);
    return true;
  }

  parseFEN(INITIAL_FEN);

  return {
    getBoard: () => [...board],
    getTurn: () => turn,
    getLegalMoves: (sq) => {
      const all = legalMoves();
      return sq !== undefined ? all.filter(m => m.from === sq) : all;
    },
    makeMove: doMove,
    undoMove,
    toFEN,
    gameStatus,
    getHistory: () => history.map(h => ({ ...h })),
    uciToMove,
    moveToUCI,
    reset: () => parseFEN(INITIAL_FEN),
    parseFEN,
    isWhite, isBlack, colorOf,
    row, col, rc,
  };
}

// ===== STOCKFISH ENGINE WRAPPER =====
function createStockfish(onReady) {
  let worker = null;
  let ready = false;
  let onBestMove = null;

  function init() {
    try {
      worker = new Worker("https://cdn.jsdelivr.net/npm/stockfish.js@10.0.2/stockfish.js");
    } catch (e) {
      return;
    }

    worker.onmessage = (e) => {
      const line = typeof e.data === "string" ? e.data : (e.data?.data || "");
      if (line === "uciok") {
        worker.postMessage("isready");
      } else if (line === "readyok") {
        ready = true;
        if (onReady) onReady();
      } else if (line.startsWith("bestmove")) {
        const parts = line.split(" ");
        if (onBestMove) onBestMove(parts[1]);
      }
    };

    worker.postMessage("uci");
  }

  function search(fen, depth, callback) {
    if (!ready) { callback(null); return; }
    onBestMove = callback;
    worker.postMessage("position fen " + fen);
    worker.postMessage("go depth " + depth);
  }

  function stop() {
    if (worker) worker.postMessage("stop");
  }

  function destroy() {
    if (worker) { worker.terminate(); worker = null; }
  }

  init();
  return { search, stop, destroy, isReady: () => ready };
}

// ===== STYLES =====
const STYLE = `
.chess-app{display:flex;gap:20px;padding:16px;max-width:960px;margin:0 auto;flex-wrap:wrap;justify-content:center;font-family:var(--font-display,'Sora',system-ui,sans-serif)}
.chess-board-wrap{position:relative;flex-shrink:0}
.chess-board{display:grid;grid-template-columns:repeat(8,1fr);border:2px solid var(--line,#283a5a);border-radius:var(--radius,8px);overflow:hidden;user-select:none;-webkit-user-select:none;touch-action:none;box-shadow:0 8px 32px -8px rgba(0,0,0,.6)}
.chess-sq{position:relative;display:flex;align-items:center;justify-content:center;aspect-ratio:1;cursor:pointer;transition:background .15s}
.chess-sq.light{background:color-mix(in srgb,var(--card,#0f1726) 70%,var(--acc,#00d4ff) 8%)}
.chess-sq.dark{background:color-mix(in srgb,var(--bg,#070a12) 80%,var(--acc,#00d4ff) 12%)}
.chess-sq.selected{box-shadow:inset 0 0 0 3px var(--acc,#00d4ff),inset 0 0 20px color-mix(in srgb,var(--acc,#00d4ff) 30%,transparent)}
.chess-sq.last-move{background:color-mix(in srgb,var(--acc-2,#7c5cff) 20%,var(--bg,#070a12))}
.chess-sq.check{box-shadow:inset 0 0 0 3px var(--bad,#ff5c6c),inset 0 0 24px color-mix(in srgb,var(--bad,#ff5c6c) 40%,transparent)}
.chess-sq .chess-dot{position:absolute;width:28%;height:28%;border-radius:50%;background:color-mix(in srgb,var(--acc,#00d4ff) 50%,transparent);pointer-events:none;z-index:2}
.chess-sq .chess-capture-dot{position:absolute;width:85%;height:85%;border-radius:50%;border:5px solid color-mix(in srgb,var(--acc,#00d4ff) 40%,transparent);pointer-events:none;z-index:2;box-sizing:border-box}
.chess-piece{width:80%;height:80%;z-index:3;pointer-events:none;filter:drop-shadow(0 2px 3px rgba(0,0,0,.4));transition:transform .1s}
.chess-sq:hover .chess-piece{transform:scale(1.05)}
.chess-piece.dragging{position:fixed;width:60px;height:60px;z-index:1000;pointer-events:none;filter:drop-shadow(0 4px 12px rgba(0,0,0,.6));transform:scale(1.15);transition:none}
.chess-coords{position:absolute;font-size:.65rem;font-family:var(--font-mono,monospace);color:var(--mut,#7a93b8);opacity:.7;pointer-events:none;z-index:4;font-weight:600}
.chess-coord-file{bottom:2px;right:4px}
.chess-coord-rank{top:2px;left:4px}
.chess-side{display:flex;flex-direction:column;gap:12px;min-width:220px;max-width:300px;flex:1}
.chess-status{padding:10px 14px;border-radius:var(--radius,8px);background:var(--card,#0f1726);border:1px solid var(--line,#283a5a);font-size:.85rem;font-weight:600;text-align:center;color:var(--txt,#e6eefc)}
.chess-status.check{border-color:var(--bad,#ff5c6c);color:var(--bad,#ff5c6c)}
.chess-status.over{border-color:var(--acc,#00d4ff);color:var(--acc,#00d4ff)}
.chess-controls{display:flex;gap:8px;flex-wrap:wrap}
.chess-controls button{background:var(--card2,#151f34);color:var(--txt,#e6eefc);border:1px solid var(--line,#283a5a);border-radius:var(--radius,8px);padding:7px 13px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .2s}
.chess-controls button:hover{border-color:var(--acc,#00d4ff);background:color-mix(in srgb,var(--acc,#00d4ff) 10%,var(--card2,#151f34));color:var(--acc,#00d4ff)}
.chess-controls button.danger:hover{border-color:var(--bad,#ff5c6c);color:var(--bad,#ff5c6c);background:color-mix(in srgb,var(--bad,#ff5c6c) 8%,var(--card2,#151f34))}
.chess-depth{display:flex;align-items:center;gap:8px;font-size:.78rem;color:var(--txt-2,#aebfdd)}
.chess-depth input[type=range]{flex:1;accent-color:var(--acc,#00d4ff);height:4px}
.chess-depth span{font-family:var(--font-mono,monospace);min-width:22px;text-align:right;color:var(--acc,#00d4ff);font-weight:700}
.chess-captured{display:flex;gap:2px;flex-wrap:wrap;min-height:24px;font-size:1.1rem;opacity:.8}
.chess-moves{background:var(--card,#0f1726);border:1px solid var(--line,#283a5a);border-radius:var(--radius,8px);padding:10px;flex:1;overflow-y:auto;max-height:280px;font-family:var(--font-mono,monospace);font-size:.78rem;line-height:1.7;color:var(--txt-2,#aebfdd)}
.chess-moves .chess-move-num{color:var(--mut,#7a93b8);margin-right:4px}
.chess-moves .chess-move-w,.chess-moves .chess-move-b{display:inline-block;padding:1px 5px;border-radius:4px;cursor:pointer;margin:0 1px;transition:background .15s}
.chess-moves .chess-move-w:hover,.chess-moves .chess-move-b:hover{background:color-mix(in srgb,var(--acc,#00d4ff) 15%,transparent)}
.chess-engine-status{font-size:.72rem;color:var(--mut,#7a93b8);text-align:center;padding:4px}
.chess-promo-overlay{position:absolute;inset:0;background:rgba(0,0,0,.6);z-index:10;display:flex;align-items:center;justify-content:center;border-radius:var(--radius,8px)}
.chess-promo-picker{display:flex;gap:6px;background:var(--card,#0f1726);border:1px solid var(--acc,#00d4ff);border-radius:var(--radius,8px);padding:12px;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.chess-promo-opt{width:52px;height:52px;cursor:pointer;border:2px solid var(--line,#283a5a);border-radius:var(--btn-radius,4px);background:var(--card2,#151f34);display:flex;align-items:center;justify-content:center;transition:all .15s}
.chess-promo-opt:hover{border-color:var(--acc,#00d4ff);background:color-mix(in srgb,var(--acc,#00d4ff) 15%,var(--card2,#151f34));transform:scale(1.1)}
.chess-promo-opt svg{width:36px;height:36px}
.chess-label{font-size:.72rem;color:var(--mut,#7a93b8);text-transform:uppercase;letter-spacing:.08em;font-weight:600}
.chess-thinking{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--acc,#00d4ff);animation:chess-pulse 1s ease-in-out infinite}
@keyframes chess-pulse{0%,100%{opacity:.3;transform:scale(.8)}50%{opacity:1;transform:scale(1.2)}}
@media(max-width:640px){
  .chess-app{flex-direction:column;align-items:center;padding:8px;gap:12px}
  .chess-side{min-width:unset;max-width:unset;width:100%}
  .chess-board-wrap{width:min(100%,400px)}
  .chess-moves{max-height:160px}
}
`;

// ===== RENDERER =====
export function render(root) {
  let styleEl = document.getElementById("chess-styles");
  if (!styleEl) {
    styleEl = document.createElement("style");
    styleEl.id = "chess-styles";
    styleEl.textContent = STYLE;
    document.head.appendChild(styleEl);
  }

  const game = createGame();
  let flipped = false;
  let selectedSq = null;
  let legalForSelected = [];
  let lastMove = null;
  let playerColor = "w";
  let depth = 8;
  let thinking = false;
  let gameOver = false;
  let promoCallback = null;
  let dragState = null;
  let stockfish = null;

  root.innerHTML = `<div class="chess-app">
    <div class="chess-board-wrap">
      <div class="chess-board" id="chess-board"></div>
    </div>
    <div class="chess-side">
      <div class="chess-status" id="chess-status">Your move</div>
      <div class="chess-label">Captured</div>
      <div class="chess-captured" id="chess-captured-w"></div>
      <div class="chess-captured" id="chess-captured-b"></div>
      <div class="chess-controls">
        <button id="chess-new">New Game</button>
        <button id="chess-undo">Undo</button>
        <button id="chess-flip">Flip</button>
        <button id="chess-resign" class="danger">Resign</button>
      </div>
      <div class="chess-depth">
        <span class="chess-label">Depth</span>
        <input type="range" id="chess-depth" min="1" max="20" value="8">
        <span id="chess-depth-val">8</span>
      </div>
      <div class="chess-label">Moves</div>
      <div class="chess-moves" id="chess-moves"></div>
      <div class="chess-engine-status" id="chess-engine-status">Loading engine...</div>
    </div>
  </div>`;

  const boardEl = root.querySelector("#chess-board");
  const statusEl = root.querySelector("#chess-status");
  const movesEl = root.querySelector("#chess-moves");
  const capturedW = root.querySelector("#chess-captured-w");
  const capturedB = root.querySelector("#chess-captured-b");
  const engineStatus = root.querySelector("#chess-engine-status");
  const depthInput = root.querySelector("#chess-depth");
  const depthVal = root.querySelector("#chess-depth-val");

  depthInput.oninput = () => { depth = +depthInput.value; depthVal.textContent = depth; };

  stockfish = createStockfish(() => {
    engineStatus.textContent = "Stockfish ready";
    setTimeout(() => { engineStatus.style.opacity = "0"; }, 2000);
  });

  function drawBoard() {
    boardEl.innerHTML = "";
    const board = game.getBoard();
    const kingInCheck = game.gameStatus().includes("check");

    for (let vi = 0; vi < 64; vi++) {
      const r = flipped ? 7 - Math.floor(vi / 8) : Math.floor(vi / 8);
      const c = flipped ? 7 - (vi % 8) : vi % 8;
      const sq = game.rc(r, c);
      const isLight = (r + c) % 2 === 0;
      const piece = board[sq];

      const div = document.createElement("div");
      div.className = "chess-sq " + (isLight ? "light" : "dark");
      div.dataset.sq = sq;

      if (lastMove && (sq === lastMove.from || sq === lastMove.to)) div.classList.add("last-move");
      if (sq === selectedSq) div.classList.add("selected");

      if (kingInCheck && piece && piece.toUpperCase() === "K" && game.colorOf(piece) === game.getTurn()) {
        div.classList.add("check");
      }

      const isLegalTarget = legalForSelected.some(m => m.to === sq);
      if (isLegalTarget) {
        const dot = document.createElement("div");
        dot.className = board[sq] ? "chess-capture-dot" : "chess-dot";
        div.appendChild(dot);
      }

      if (piece) {
        const svg = document.createElement("div");
        svg.className = "chess-piece";
        svg.innerHTML = PIECE_SVG[piece];
        svg.dataset.sq = sq;
        div.appendChild(svg);
      }

      if ((flipped ? 7 - c : c) === 7) {
        const coord = document.createElement("span");
        coord.className = "chess-coords chess-coord-rank";
        coord.textContent = 8 - r;
        div.appendChild(coord);
      }
      if ((flipped ? r : 7 - r) === 0) {
        const coord = document.createElement("span");
        coord.className = "chess-coords chess-coord-file";
        coord.textContent = FILES[c];
        div.appendChild(coord);
      }

      boardEl.appendChild(div);
    }
  }

  function updateStatus() {
    const status = game.gameStatus();
    statusEl.className = "chess-status";
    if (status === "playing") {
      if (thinking) {
        statusEl.innerHTML = `<span class="chess-thinking"></span> Stockfish thinking...`;
      } else {
        statusEl.textContent = game.getTurn() === playerColor ? "Your move" : "Engine's turn";
      }
    } else if (status.includes("check") && !status.includes("checkmate")) {
      statusEl.classList.add("check");
      statusEl.textContent = status;
    } else {
      statusEl.classList.add("over");
      statusEl.textContent = status;
      gameOver = true;
    }
  }

  function updateMoves() {
    const hist = game.getHistory();
    let html = "";
    for (let i = 0; i < hist.length; i += 2) {
      const num = Math.floor(i / 2) + 1;
      html += `<span class="chess-move-num">${num}.</span>`;
      html += `<span class="chess-move-w">${hist[i].alg}</span> `;
      if (hist[i + 1]) html += `<span class="chess-move-b">${hist[i + 1].alg}</span> `;
    }
    movesEl.innerHTML = html;
    movesEl.scrollTop = movesEl.scrollHeight;
  }

  function updateCaptured() {
    const hist = game.getHistory();
    const wCaptured = [], bCaptured = [];
    for (const h of hist) {
      if (h.state.captured) {
        if (game.isWhite(h.state.captured)) wCaptured.push(h.state.captured);
        else bCaptured.push(h.state.captured);
      }
    }
    const order = { q: 0, r: 1, b: 2, n: 3, p: 4, Q: 0, R: 1, B: 2, N: 3, P: 4 };
    wCaptured.sort((a, b) => order[a] - order[b]);
    bCaptured.sort((a, b) => order[a] - order[b]);
    capturedW.innerHTML = wCaptured.map(p => `<span>${PIECE_CHARS[p]}</span>`).join("");
    capturedB.innerHTML = bCaptured.map(p => `<span>${PIECE_CHARS[p]}</span>`).join("");
  }

  function refresh() {
    drawBoard();
    updateStatus();
    updateMoves();
    updateCaptured();
  }

  function showPromotion(from, to) {
    return new Promise(resolve => {
      const overlay = document.createElement("div");
      overlay.className = "chess-promo-overlay";
      const picker = document.createElement("div");
      picker.className = "chess-promo-picker";
      const color = game.getTurn();
      const pieces = color === "w" ? ["Q", "R", "B", "N"] : ["q", "r", "b", "n"];
      const flags = [4, 5, 6, 7];

      pieces.forEach((p, i) => {
        const opt = document.createElement("div");
        opt.className = "chess-promo-opt";
        opt.innerHTML = PIECE_SVG[p];
        opt.onclick = () => {
          overlay.remove();
          resolve(flags[i]);
        };
        picker.appendChild(opt);
      });

      overlay.appendChild(picker);
      overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); resolve(null); } };
      boardEl.parentElement.appendChild(overlay);
    });
  }

  async function tryMove(fromSq, toSq) {
    if (gameOver || thinking) return;
    if (game.getTurn() !== playerColor) return;

    const legal = game.getLegalMoves(fromSq);
    const matching = legal.filter(m => m.to === toSq);
    if (!matching.length) return;

    let move;
    const isPromo = matching.some(m => m.flags >= 4 && m.flags <= 7);
    if (isPromo) {
      const flag = await showPromotion(fromSq, toSq);
      if (flag === null) { selectedSq = null; legalForSelected = []; refresh(); return; }
      move = matching.find(m => m.flags === flag);
    } else {
      move = matching[0];
    }

    if (!move) return;

    lastMove = { from: move.from, to: move.to };
    game.makeMove(move);
    selectedSq = null;
    legalForSelected = [];
    refresh();

    if (!gameOver) engineMove();
  }

  function engineMove() {
    if (gameOver) return;
    thinking = true;
    updateStatus();

    stockfish.search(game.toFEN(), depth, (bestUci) => {
      thinking = false;
      if (!bestUci || gameOver) { updateStatus(); return; }
      const move = game.uciToMove(bestUci);
      if (move) {
        lastMove = { from: move.from, to: move.to };
        game.makeMove(move);
      }
      refresh();
    });
  }

  // Click to move
  boardEl.addEventListener("click", (e) => {
    if (dragState) return;
    const sqEl = e.target.closest(".chess-sq");
    if (!sqEl) return;
    const sq = +sqEl.dataset.sq;
    const board = game.getBoard();

    if (selectedSq !== null) {
      if (legalForSelected.some(m => m.to === sq)) {
        tryMove(selectedSq, sq);
        return;
      }
    }

    if (board[sq] && game.colorOf(board[sq]) === playerColor && game.getTurn() === playerColor && !gameOver && !thinking) {
      selectedSq = sq;
      legalForSelected = game.getLegalMoves(sq);
    } else {
      selectedSq = null;
      legalForSelected = [];
    }
    drawBoard();
  });

  // Drag to move
  function startDrag(sq, x, y) {
    const board = game.getBoard();
    if (!board[sq] || game.colorOf(board[sq]) !== playerColor || game.getTurn() !== playerColor || gameOver || thinking) return;

    selectedSq = sq;
    legalForSelected = game.getLegalMoves(sq);
    drawBoard();

    const pieceEl = boardEl.querySelector(`.chess-sq[data-sq="${sq}"] .chess-piece`);
    if (!pieceEl) return;

    const clone = pieceEl.cloneNode(true);
    clone.classList.add("dragging");
    clone.style.left = (x - 30) + "px";
    clone.style.top = (y - 30) + "px";
    document.body.appendChild(clone);
    pieceEl.style.opacity = "0.2";

    dragState = { sq, clone, pieceEl };
  }

  function moveDrag(x, y) {
    if (!dragState) return;
    dragState.clone.style.left = (x - 30) + "px";
    dragState.clone.style.top = (y - 30) + "px";
  }

  function endDrag(x, y) {
    if (!dragState) return;
    dragState.clone.remove();
    if (dragState.pieceEl) dragState.pieceEl.style.opacity = "";

    const el = document.elementFromPoint(x, y);
    const sqEl = el && el.closest(".chess-sq");
    if (sqEl) {
      const toSq = +sqEl.dataset.sq;
      if (legalForSelected.some(m => m.to === toSq)) {
        dragState = null;
        tryMove(selectedSq, toSq);
        return;
      }
    }

    selectedSq = null;
    legalForSelected = [];
    dragState = null;
    drawBoard();
  }

  boardEl.addEventListener("pointerdown", (e) => {
    const sqEl = e.target.closest(".chess-sq");
    if (!sqEl) return;
    const sq = +sqEl.dataset.sq;
    const board = game.getBoard();
    if (board[sq] && game.colorOf(board[sq]) === playerColor) {
      e.preventDefault();
      startDrag(sq, e.clientX, e.clientY);
    }
  });

  document.addEventListener("pointermove", (e) => {
    if (dragState) { e.preventDefault(); moveDrag(e.clientX, e.clientY); }
  });

  document.addEventListener("pointerup", (e) => {
    if (dragState) endDrag(e.clientX, e.clientY);
  });

  // Buttons
  root.querySelector("#chess-new").onclick = () => {
    game.reset();
    selectedSq = null; legalForSelected = []; lastMove = null;
    gameOver = false; thinking = false;
    playerColor = "w";
    refresh();
  };

  root.querySelector("#chess-undo").onclick = () => {
    if (thinking || gameOver) return;
    game.undoMove();
    game.undoMove();
    selectedSq = null; legalForSelected = [];
    const hist = game.getHistory();
    lastMove = hist.length ? { from: hist[hist.length - 1].move.from, to: hist[hist.length - 1].move.to } : null;
    gameOver = false;
    refresh();
  };

  root.querySelector("#chess-flip").onclick = () => {
    flipped = !flipped;
    drawBoard();
  };

  root.querySelector("#chess-resign").onclick = () => {
    if (gameOver) return;
    gameOver = true;
    statusEl.className = "chess-status over";
    statusEl.textContent = playerColor === "w" ? "White resigns — Black wins" : "Black resigns — White wins";
  };

  refresh();
}

export const id = "chess";
export const name = "Chess vs Stockfish";
export const cat = "Games";
export const kind = "browser";
export const desc = "Play chess against Stockfish — full rules, drag-and-drop, adjustable difficulty";
