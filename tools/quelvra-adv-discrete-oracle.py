#!/usr/bin/env python3
# Test-oracle generator for the Quelvra advanced discrete-math probe corpus.
#
#   python3 tools/quelvra-adv-discrete-oracle.py  ->  test/quelvra/advanced-discrete.corpus.json
#
# sympy / networkx are used HERE ONLY, as independent oracles for the expected answers. Nothing in
# this file is shipped or imported by the engine.
#
# Expectation items (checked by test/quelvra/advanced-discrete.test.js):
#   ["eq", label, value]            an answer with this label (case-insensitive) equals value
#                                   (tree answers: symbolic equivalence; text answers: whitespace-insensitive)
#   ["set", label, value]           text answer equal to value as a (nested) set
#   ["seq", label, var, start, terms]  tree answer evaluated at var = start.. gives terms
#   ["path", label, edges, directed, s, t, dist]  text path is a valid s-t path of length dist
#   ["topo", label, edges]          text order is a topological order of the digraph
#   ["logic", label, vars, rows]    text formula is true exactly on the listed rows (bit i = var i, MSB first)
#   ["status", s]                   result.solutionStatus == s
#   ["refuse"]                      the request must be refused (no answer shown)
import json, itertools, math, os
from fractions import Fraction as F
import sympy as sp
import networkx as nx

OUT = os.path.join(os.path.dirname(__file__), "..", "test", "quelvra", "advanced-discrete.corpus.json")
CASES = []
def case(area, inp, *expect):
    CASES.append({"area": area, "input": inp, "expect": [list(e) for e in expect]})

def yn(b): return "yes" if b else "no"
def fr(q):
    q = sp.Rational(q)
    return str(q.p) if q.q == 1 else f"{q.p}/{q.q}"

# ============================================================ 1. recurrences and sequences
n, x, k = sp.symbols("n x k")
def rec_terms(coeffs, init, forcing=lambda m: 0, count=12):
    a = list(init)
    while len(a) < count:
        m = len(a)
        a.append(sum(c * a[m - 1 - i] for i, c in enumerate(coeffs)) + forcing(m))
    return a[:count]

A = "seq"
t = rec_terms([5, -6], [1, 4]); case(A, "rsolve(a(n) = 5a(n-1) - 6a(n-2), a(0) = 1, a(1) = 4)", ["seq", "a(n)", "n", 0, [int(v) for v in t]])
t = rec_terms([1, 1], [0, 1]); case(A, "solve the recurrence a_n = a_{n-1} + a_{n-2} with a_0 = 0, a_1 = 1", ["seq", "a(n)", "n", 0, t])
t = rec_terms([3, -2], [1, 3]); case(A, "solve the recurrence relation a_n = 3a_{n-1} - 2a_{n-2}, a_0 = 1, a_1 = 3", ["seq", "a(n)", "n", 0, t])
t = rec_terms([2], [3], lambda m: 1); case(A, "solve the recurrence a(n) = 2a(n-1) + 1, a(0) = 3", ["seq", "a(n)", "n", 0, t])
t = rec_terms([4, -4], [1, 6]); case(A, "rsolve(a(n) = 4a(n-1) - 4a(n-2), a(0) = 1, a(1) = 6)", ["seq", "a(n)", "n", 0, t])
t = rec_terms([1], [0], lambda m: m); case(A, "solve the recurrence a_n = a_{n-1} + n, a_0 = 0", ["seq", "a(n)", "n", 0, t])
t = rec_terms([2], [1], lambda m: 3 ** m); case(A, "rsolve(a(n) = 2a(n-1) + 3^n, a(0) = 1)", ["seq", "a(n)", "n", 0, t])
t = rec_terms([6, -11, 6], [2, 5, 15]); case(A, "solve the recurrence a(n) = 6a(n-1) - 11a(n-2) + 6a(n-3) with a(0) = 2, a(1) = 5, a(2) = 15", ["seq", "a(n)", "n", 0, t])
t = rec_terms([2], [1], lambda m: 2 ** m); case(A, "solve the recurrence relation a_n = 2a_{n-1} + 2^n, a_0 = 1", ["seq", "a(n)", "n", 0, t])
t = rec_terms([1, 2], [2, 1]); case(A, "rsolve(a(n) = a(n-1) + 2a(n-2), a(0) = 2, a(1) = 1)", ["seq", "a(n)", "n", 0, t])
# generating functions
def gf_case(inp, expr): case(A, inp, ["eq", "generating function", str(sp.simplify(expr))])
gf_case("genfunc(a(n) = a(n-1) + a(n-2), a(0) = 0, a(1) = 1)", x / (1 - x - x**2))
gf_case("generating function of the sequence a(n) = 3a(n-1), a(0) = 2", 2 / (1 - 3 * x))
gf_case("find the generating function for a_n = 2^n + 1", 1 / (1 - 2 * x) + 1 / (1 - x))
gf_case("genfunc(n^2, n)", sp.summation(n**2 * x**n, (n, 0, sp.oo)).simplify() if False else x * (1 + x) / (1 - x)**3)
gf_case("ordinary generating function of a(n) = n + 1", 1 / (1 - x)**2)
gf_case("genfunc(a(n) = 2a(n-1) + 1, a(0) = 0)", x / ((1 - x) * (1 - 2 * x)))
# coefficient extraction
def coeff_case(inp, f, m): case(A, inp, ["eq", "coefficient", str(sp.series(f, x, 0, m + 1).removeO().coeff(x, m))])
coeff_case("coefficient of x^10 in 1/(1-x-x^2)", 1 / (1 - x - x**2), 10)
coeff_case("find the coefficient of x^5 in (1+x)^8", (1 + x)**8, 5)
coeff_case("coefficient(1/((1-x)(1-x^2)), x, 7)", 1 / ((1 - x) * (1 - x**2)), 7)
coeff_case("coefficient of x^6 in 1/(1-x)^3", 1 / (1 - x)**3, 6)
coeff_case("coefficient of x^4 in (1+2x)^5 (1-x)^2", (1 + 2 * x)**5 * (1 - x)**2, 4)
coeff_case("coefficient of x^9 in x^2/(1-2x)", x**2 / (1 - 2 * x), 9)
# sequence identification (conjectures)
case(A, "findsequence(1, 4, 9, 16, 25)", ["eq", "formula", "(n+1)^2"], ["eq", "next term", "36"])
case(A, "find the next term in the sequence 2, 6, 12, 20, 30", ["eq", "next term", "42"])
case(A, "identify the sequence 1, 1, 2, 3, 5, 8, 13, 21", ["eq", "next term", "34"])
case(A, "what is the nth term of 3, 7, 11, 15, 19", ["eq", "formula", "4n+3"])
case(A, "find the next term of 2, 6, 18, 54, 162", ["eq", "next term", "486"])
case(A, "findsequence(1, 3)", ["refuse"])
case(A, "next term of 1, 8, 27, 64, 125, 216", ["eq", "next term", "343"])

# ============================================================ 2. graph theory
A = "graph"
def es(edges, w=False, directed=False):
    arrow = "->" if directed else "-"
    return ", ".join(f"{u}{arrow}{v}" + (f":{d}" if w else "") for (u, v, *rest) in edges for d in [rest[0] if rest else None])
def G(edges, directed=False):
    g = nx.DiGraph() if directed else nx.Graph()
    for e in edges:
        if len(e) == 3: g.add_edge(e[0], e[1], weight=e[2], capacity=e[2])
        else: g.add_edge(e[0], e[1])
    return g
E1 = [(1, 2), (2, 3), (3, 1), (3, 4)]
g = G(E1); case(A, "degrees({1-2, 2-3, 3-1, 3-4})", ["eq", "degree sequence", ", ".join(str(d) for d in sorted((d for _, d in g.degree()), reverse=True))])
E2 = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "A"), ("A", "C")]
g = G(E2); case(A, "find the degree of each vertex in the graph with edges A-B, B-C, C-D, D-A, A-C", ["eq", "degree sequence", ", ".join(str(d) for d in sorted((d for _, d in g.degree()), reverse=True))])
E3 = [(1, 2), (2, 3), (4, 5), (6, 7), (7, 8), (8, 6)]
g = G(E3); case(A, "components({1-2, 2-3, 4-5, 6-7, 7-8, 8-6})", ["eq", "components", str(nx.number_connected_components(g))], ["eq", "connected", "no"])
case(A, "is the graph with edges 1-2, 2-3, 3-4, 4-1 connected", ["eq", "connected", "yes"])
W1 = [("A", "B", 4), ("A", "C", 2), ("B", "C", 1), ("B", "D", 5), ("C", "D", 8), ("C", "E", 10), ("D", "E", 2), ("D", "F", 6), ("E", "F", 3)]
g = G(W1); d = nx.dijkstra_path_length(g, "A", "F")
case(A, "shortestpath({A-B:4, A-C:2, B-C:1, B-D:5, C-D:8, C-E:10, D-E:2, D-F:6, E-F:3}, A, F)", ["eq", "distance", str(d)], ["path", "path", [list(e) for e in W1], False, "A", "F", d])
case(A, "find the shortest path from A to E in the graph with edges A-B:4, A-C:2, B-C:1, B-D:5, C-D:8, C-E:10, D-E:2, D-F:6, E-F:3", ["eq", "distance", str(nx.dijkstra_path_length(g, "A", "E"))])
U1 = [(1, 2), (2, 3), (3, 4), (1, 5), (5, 4), (2, 6)]
g = G(U1); case(A, "shortest path from 1 to 4 in the graph 1-2, 2-3, 3-4, 1-5, 5-4, 2-6", ["eq", "distance", str(nx.shortest_path_length(g, 1, 4))])
D1 = [("s", "a", 2), ("s", "b", 5), ("a", "b", 1), ("b", "t", 2), ("a", "t", 6)]
g = G(D1, True); case(A, "shortestpath({s->a:2, s->b:5, a->b:1, b->t:2, a->t:6}, s, t)", ["eq", "distance", str(nx.dijkstra_path_length(g, "s", "t"))])
g = G(W1); T = nx.minimum_spanning_tree(g)
case(A, "mst({A-B:4, A-C:2, B-C:1, B-D:5, C-D:8, C-E:10, D-E:2, D-F:6, E-F:3})", ["eq", "total weight", str(int(T.size(weight="weight")))])
W2 = [(1, 2, 7), (1, 4, 5), (2, 3, 8), (2, 4, 9), (2, 5, 7), (3, 5, 5), (4, 5, 15), (4, 6, 6), (5, 6, 8), (5, 7, 9), (6, 7, 11)]
g = G(W2); case(A, "find the minimum spanning tree of the graph with edges 1-2:7, 1-4:5, 2-3:8, 2-4:9, 2-5:7, 3-5:5, 4-5:15, 4-6:6, 5-6:8, 5-7:9, 6-7:11", ["eq", "total weight", str(int(nx.minimum_spanning_tree(g).size(weight="weight")))])
def ntrees(g): return int(round(sp.Matrix(nx.laplacian_matrix(g).todense())[1:, 1:].det()))
case(A, "number of spanning trees of K5", ["eq", "spanning trees", str(ntrees(nx.complete_graph(5)))])
case(A, "spanningtrees({1-2, 2-3, 3-4, 4-1, 1-3})", ["eq", "spanning trees", str(ntrees(G([(1, 2), (2, 3), (3, 4), (4, 1), (1, 3)])))])
case(A, "how many spanning trees does K3,3 have", ["eq", "spanning trees", str(ntrees(nx.complete_bipartite_graph(3, 3)))])
case(A, "number of spanning trees of the Petersen graph", ["eq", "spanning trees", str(ntrees(nx.petersen_graph()))])
case(A, "is the graph with edges 1-2, 2-3, 3-4, 4-1 bipartite", ["eq", "bipartite", "yes"])
case(A, "bipartite({1-2, 2-3, 3-1})", ["eq", "bipartite", "no"])
case(A, "is C7 bipartite", ["eq", "bipartite", "no"])
case(A, "is Q3 bipartite", ["eq", "bipartite", "yes"])
KB = [("A", "B"), ("A", "B"), ("A", "C"), ("A", "C"), ("A", "D"), ("B", "D"), ("C", "D")]
case(A, "does the graph with edges A-B, A-B, A-C, A-C, A-D, B-D, C-D have an Euler path", ["eq", "euler path", "no"], ["eq", "euler circuit", "no"])
case(A, "eulerpath({1-2, 2-3, 3-4, 4-1, 1-3})", ["eq", "euler path", "yes"], ["eq", "euler circuit", "no"])
case(A, "does K5 have an Euler circuit", ["eq", "euler circuit", "yes"])
case(A, "find an Euler circuit in the graph with edges 1-2, 2-3, 3-1, 1-4, 4-5, 5-1", ["eq", "euler circuit", "yes"])
def has_ham(g, cycle):
    nodes = list(g.nodes)
    for p in itertools.permutations(nodes):
        if all(g.has_edge(p[i], p[i + 1]) for i in range(len(p) - 1)) and (not cycle or g.has_edge(p[-1], p[0])): return True
    return False
pg = nx.petersen_graph()
case(A, "does the Petersen graph have a Hamiltonian cycle", ["eq", "hamiltonian cycle", "no"], ["eq", "hamiltonian path", "yes"])
case(A, "hamiltonian({1-2, 2-3, 3-4, 4-5, 5-1, 1-3})", ["eq", "hamiltonian cycle", yn(has_ham(G([(1, 2), (2, 3), (3, 4), (4, 5), (5, 1), (1, 3)]), True))])
g = G([(1, 2), (1, 3), (1, 4)]); case(A, "is there a Hamiltonian path in the graph with edges 1-2, 1-3, 1-4", ["eq", "hamiltonian path", yn(has_ham(g, False))])
case(A, "does K_{2,3} have a Hamiltonian cycle", ["eq", "hamiltonian cycle", "no"])
def chrom_num(g):
    for kk in range(1, g.number_of_nodes() + 1):
        for col in itertools.product(range(kk), repeat=g.number_of_nodes()):
            m = dict(zip(g.nodes, col))
            if all(m[u] != m[v] for u, v in g.edges): return kk
case(A, "chromatic number of the Petersen graph", ["eq", "chromatic number", "3"])
case(A, "chromaticnumber({1-2, 2-3, 3-4, 4-5, 5-1})", ["eq", "chromatic number", str(chrom_num(nx.cycle_graph(5)))])
case(A, "what is the chromatic number of K4", ["eq", "chromatic number", "4"])
case(A, "chromatic number of the wheel W6", ["eq", "chromatic number", str(chrom_num(nx.wheel_graph(7)))])
kk = sp.symbols("k")
def chrom_poly(g):
    # oracle: interpolate brute-force colouring counts
    nn = g.number_of_nodes(); pts = []
    for c in range(nn + 1):
        cnt = sum(1 for col in itertools.product(range(c), repeat=nn) if all(col[list(g.nodes).index(u)] != col[list(g.nodes).index(v)] for u, v in g.edges))
        pts.append((c, cnt))
    return sp.expand(sp.interpolate(pts, kk))
case(A, "chromatic polynomial of C4", ["eq", "chromatic polynomial", str(chrom_poly(nx.cycle_graph(4)))])
case(A, "chromaticpoly({1-2, 2-3, 3-1, 3-4})", ["eq", "chromatic polynomial", str(chrom_poly(G([(1, 2), (2, 3), (3, 1), (3, 4)])))])
case(A, "find the chromatic polynomial of K4", ["eq", "chromatic polynomial", str(sp.expand(kk * (kk - 1) * (kk - 2) * (kk - 3)))])
case(A, "is K5 planar", ["eq", "planar", "no"])
case(A, "is K3,3 planar", ["eq", "planar", "no"])
case(A, "is Q3 planar", ["eq", "planar", "yes"])
case(A, "planar({1-2, 1-3, 1-4, 2-3, 2-4, 3-4})", ["eq", "planar", "yes"])
case(A, "is the Petersen graph planar", ["eq", "planar", "no"])
F1 = [("s", "a", 10), ("s", "b", 5), ("a", "b", 15), ("a", "t", 10), ("b", "t", 10)]
g = G(F1, True); case(A, "maxflow({s->a:10, s->b:5, a->b:15, a->t:10, b->t:10}, s, t)", ["eq", "max flow", str(nx.maximum_flow_value(g, "s", "t"))])
F2 = [("s", "a", 16), ("s", "c", 13), ("a", "b", 12), ("c", "a", 4), ("b", "c", 9), ("c", "d", 14), ("d", "b", 7), ("b", "t", 20), ("d", "t", 4)]
g = G(F2, True); case(A, "find the maximum flow from s to t in the network s->a:16, s->c:13, a->b:12, c->a:4, b->c:9, c->d:14, d->b:7, b->t:20, d->t:4", ["eq", "max flow", str(nx.maximum_flow_value(g, "s", "t"))])
T1 = [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("d", "e")]
case(A, "toposort({a->b, a->c, b->d, c->d, d->e})", ["topo", "topological order", [list(e) for e in T1]])
T2 = [(5, 11), (7, 11), (7, 8), (3, 8), (3, 10), (11, 2), (11, 9), (11, 10), (8, 9)]
case(A, "topological sort of the directed graph 5->11, 7->11, 7->8, 3->8, 3->10, 11->2, 11->9, 11->10, 8->9", ["topo", "topological order", [list(e) for e in T2]])
case(A, "toposort({1->2, 2->3, 3->1})", ["eq", "acyclic", "no"])
G1 = [(1, 2), (2, 3), (3, 4), (4, 1)]; G2 = [("a", "c"), ("c", "b"), ("b", "d"), ("d", "a")]
case(A, "isomorphic({1-2, 2-3, 3-4, 4-1}, {a-c, c-b, b-d, d-a})", ["eq", "isomorphic", yn(nx.is_isomorphic(G(G1), G(G2)))])
H1 = [(1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 1)]; H2 = [(1, 2), (2, 3), (3, 1), (4, 5), (5, 6), (6, 4)]
case(A, "are the graphs {1-2, 2-3, 3-4, 4-5, 5-6, 6-1} and {1-2, 2-3, 3-1, 4-5, 5-6, 6-4} isomorphic", ["eq", "isomorphic", yn(nx.is_isomorphic(G(H1), G(H2)))])
case(A, "is the Petersen graph isomorphic to the graph {0-2, 2-4, 4-1, 1-3, 3-0, 0-5, 1-6, 2-7, 3-8, 4-9, 5-6, 6-7, 7-8, 8-9, 9-5}",
     ["eq", "isomorphic", yn(nx.is_isomorphic(nx.petersen_graph(), G([(0, 2), (2, 4), (4, 1), (1, 3), (3, 0), (0, 5), (1, 6), (2, 7), (3, 8), (4, 9), (5, 6), (6, 7), (7, 8), (8, 9), (9, 5)])))])
case(A, "degrees of the graph with adjacency matrix [[0,1,1,0],[1,0,1,1],[1,1,0,1],[0,1,1,0]]", ["eq", "degree sequence", "3, 3, 2, 2"])

# ============================================================ 3. logic
A = "logic"
P, Q, R, S = sp.symbols("p q r s")
def rows_of(expr, vs):
    return [i for i, bits in enumerate(itertools.product([False, True], repeat=len(vs))) if bool(expr.subs(dict(zip(vs, bits))))]
def classify(expr, vs):
    rs = rows_of(expr, vs); m = 2 ** len(vs)
    return "tautology" if len(rs) == m else "contradiction" if not rs else "contingent"
from sympy.logic.boolalg import Implies, Equivalent, Xor, Nand, Nor
e = Implies(P, Q); case(A, "truthtable(p -> q)", ["eq", "true rows", str(len(rows_of(e, [P, Q])))], ["eq", "classification", classify(e, [P, Q])])
e = (P & Q) | ~R; case(A, "truth table of (p and q) or not r", ["eq", "true rows", str(len(rows_of(e, [P, Q, R])))])
e = Equivalent(P, Q) & Xor(P, R); case(A, "truthtable((p <-> q) and (p xor r))", ["eq", "true rows", str(len(rows_of(e, [P, Q, R])))])
e = P | ~P; case(A, "is p or not p a tautology", ["eq", "classification", "tautology"])
e = Implies(Implies(P, Q) & Implies(Q, R), Implies(P, R)); case(A, "tautology(((p -> q) and (q -> r)) -> (p -> r))", ["eq", "classification", classify(e, [P, Q, R])])
case(A, "is p and not p a contradiction", ["eq", "classification", "contradiction"])
e = (P | Q) & (~P | R) & (~Q) & (~R); case(A, "is (p or q) and (not p or r) and not q and not r satisfiable", ["eq", "satisfiable", yn(bool(sp.satisfiable(e)))])
e = (P | Q) & (~P | ~Q); case(A, "satisfiable((p or q) and (not p or not q))", ["eq", "satisfiable", "yes"])
case(A, "is p -> q equivalent to not p or q", ["eq", "equivalent", "yes"])
case(A, "logicequiv(p -> q, q -> p)", ["eq", "equivalent", "no"])
case(A, "are not (p and q) and not p or not q logically equivalent", ["eq", "equivalent", "yes"])
case(A, "is p -> q equivalent to not q -> not p", ["eq", "equivalent", "yes"])
def logic_case(inp, label, expr, vs):
    case(A, inp, ["logic", label, [str(v) for v in vs], rows_of(expr, vs)])
logic_case("cnf((p and q) or r)", "cnf", (P & Q) | R, [P, Q, R])
logic_case("convert p -> (q and r) to conjunctive normal form", "cnf", Implies(P, Q & R), [P, Q, R])
logic_case("dnf(p xor q)", "dnf", Xor(P, Q), [P, Q])
logic_case("disjunctive normal form of (p -> q) and (q -> p)", "dnf", Equivalent(P, Q), [P, Q])
def minsop_case(inp, minterms, nv, dontcare=()):
    vs = sp.symbols("a b c d")[:nv]
    e = sp.SOPform(list(vs), [list(map(int, format(m, f"0{nv}b"))) for m in minterms], [list(map(int, format(m, f"0{nv}b"))) for m in dontcare])
    lits = sum(len(t.args) if isinstance(t, sp.And) else 1 for t in (e.args if isinstance(e, sp.Or) else [e]))
    rows = [i for i in range(2 ** nv) if i in minterms]
    case(A, inp, ["logic", "minimal sop", [str(v) for v in vs], rows, list(dontcare)], ["eq", "literals", str(lits)])
minsop_case("minsop(m(0, 1, 2, 5, 6, 7))", [0, 1, 2, 5, 6, 7], 3)
minsop_case("minimize the boolean function f(a,b,c,d) = sum m(0, 2, 5, 7, 8, 10, 13, 15)", [0, 2, 5, 7, 8, 10, 13, 15], 4)
minsop_case("minsop(m(1, 3, 7, 11, 15), d(0, 2, 5))", [1, 3, 7, 11, 15], 4, (0, 2, 5))
minsop_case("simplify the boolean function F(a,b,c) = sum m(1, 3, 5, 7)", [1, 3, 5, 7], 3)
case(A, "simplify the boolean expression (a and b) or (a and not b)", ["logic", "minimal sop", ["a", "b"], [2, 3]], ["eq", "literals", "1"])
case(A, "is the argument valid: p -> q, p, therefore q", ["eq", "valid", "yes"])
case(A, "validargument(p -> q, q; p)", ["eq", "valid", "no"])
case(A, "is the argument p -> q, q -> r, therefore p -> r valid", ["eq", "valid", "yes"])
case(A, "premises p or q, not p; conclusion q. is it valid", ["eq", "valid", "yes"])

# ============================================================ 4. sets, relations, functions
A = "sets"
case(A, "{1, 2, 3} union {3, 4, 5}", ["set", "result", "{1, 2, 3, 4, 5}"])
case(A, "{1, 2, 3, 4} intersect {3, 4, 5}", ["set", "result", "{3, 4}"])
case(A, "let A = {1, 2, 3, 4} and B = {3, 4, 5}; find A - B", ["set", "result", "{1, 2}"])
case(A, "symmetric difference of {1, 2, 3} and {2, 3, 4}", ["set", "result", "{1, 4}"])
case(A, "complement of {1, 3} in {1, 2, 3, 4, 5}", ["set", "result", "{2, 4, 5}"])
case(A, "power set of {a, b, c}", ["set", "power set", "{{}, {a}, {b}, {c}, {a, b}, {a, c}, {b, c}, {a, b, c}}"], ["eq", "cardinality", "8"])
case(A, "powerset({1, 2})", ["set", "power set", "{{}, {1}, {2}, {1, 2}}"])
case(A, "cartesian product of {1, 2} and {a, b, c}", ["set", "result", "{(1, a), (1, b), (1, c), (2, a), (2, b), (2, c)}"], ["eq", "cardinality", "6"])
case(A, "{1, 2} x {3, 4}", ["set", "result", "{(1, 3), (1, 4), (2, 3), (2, 4)}"])
case(A, "cardinality of {1, 2, 3, 2, 1}", ["eq", "cardinality", "3"])
case(A, "(A union B) intersect C where A = {1, 2}, B = {2, 3}, C = {2, 3, 4}", ["set", "result", "{2, 3}"])
cnt = sum(1 for i in range(1, 1001) if i % 3 == 0 or i % 5 == 0 or i % 7 == 0)
case(A, "how many integers from 1 to 1000 are divisible by 3, 5 or 7", ["eq", "count", str(cnt)])
cnt = sum(1 for i in range(1, 101) if i % 2 == 0 or i % 3 == 0)
case(A, "how many integers from 1 to 100 are divisible by 2 or 3", ["eq", "count", str(cnt)])
case(A, "|A| = 30, |B| = 25, |A ∩ B| = 10, find |A ∪ B|", ["eq", "count", "45"])
case(A, "|A| = 20, |B| = 30, |C| = 40, |A∩B| = 5, |A∩C| = 10, |B∩C| = 15, |A∩B∩C| = 3, find |A∪B∪C|", ["eq", "count", str(20 + 30 + 40 - 5 - 10 - 15 + 3)])
case(A, "how many integers from 1 to 1000 are not divisible by 2, 3 or 5", ["eq", "count", str(sum(1 for i in range(1, 1001) if i % 2 and i % 3 and i % 5))])
R1 = "{(1,1), (2,2), (3,3), (1,2), (2,1)}"
case(A, f"is the relation R = {R1} on {{1, 2, 3}} an equivalence relation", ["eq", "equivalence relation", "yes"], ["set", "equivalence classes", "{{1, 2}, {3}}"])
case(A, "relation({(1,1), (1,2), (2,2), (2,3)}, {1, 2, 3})", ["eq", "reflexive", "no"], ["eq", "symmetric", "no"], ["eq", "antisymmetric", "yes"], ["eq", "transitive", "no"])
case(A, "is the relation {(1,1), (2,2), (3,3), (1,2), (2,3), (1,3)} on {1, 2, 3} a partial order", ["eq", "partial order", "yes"])
case(A, "is R = {(1,2), (2,1)} on {1, 2} transitive", ["eq", "transitive", "no"])
case(A, "Hasse diagram of the divisibility relation on {1, 2, 3, 4, 6, 12}", ["set", "hasse edges", "{(1, 2), (1, 3), (2, 4), (2, 6), (3, 6), (4, 12), (6, 12)}"])
case(A, "equivalence classes of congruence mod 3 on {1, 2, 3, 4, 5, 6, 7}", ["set", "equivalence classes", "{{1, 4, 7}, {2, 5}, {3, 6}}"])
case(A, "is f = {(1, a), (2, b), (3, a)} from {1, 2, 3} to {a, b} injective", ["eq", "injective", "no"], ["eq", "surjective", "yes"])
case(A, "func({(1,2), (2,3), (3,1)}, {1, 2, 3}, {1, 2, 3})", ["eq", "bijective", "yes"])
case(A, "is f(x) = x^2 mod 5 injective on {0, 1, 2, 3, 4}", ["eq", "injective", "no"])
case(A, "compose f = {(1,2), (2,3), (3,1)} and g = {(1,3), (2,2), (3,1)}", ["set", "composition", "{(1, 1), (2, 3), (3, 2)}"])
case(A, "is f(x) = 3x mod 7 a bijection on {0, 1, 2, 3, 4, 5, 6}", ["eq", "bijective", "yes"])

# ============================================================ 5. abstract algebra
A = "algebra"
from sympy.combinatorics import Permutation
def perm_from_cycles(cycles, size):
    return Permutation([[c - 1 for c in cyc] for cyc in cycles], size=size)
p = perm_from_cycles([[1, 2, 3], [4, 5]], 5)
case(A, "order of the permutation (1 2 3)(4 5)", ["eq", "order", str(p.order())])
p = perm_from_cycles([[1, 3, 5], [2, 4]], 5)
case(A, "sign of the permutation (1 3 5)(2 4)", ["eq", "sign", str(p.signature())])
case(A, "is (1 2)(3 4 5) even or odd", ["eq", "parity", "odd"])
case(A, "write [2, 3, 1, 5, 4] in cycle notation", ["eq", "cycles", "(1 2 3)(4 5)"])
p = perm_from_cycles([[1, 2, 3, 4]], 4); inv = ~p
case(A, "inverse of the permutation (1 2 3 4)", ["eq", "inverse", "(1 4 3 2)"])
# right-to-left composition: (1 2 3)(2 3 4) means apply (2 3 4) first
a = perm_from_cycles([[1, 2, 3]], 4); b = perm_from_cycles([[2, 3, 4]], 4)
prod = b * a  # sympy: p*q applies p first then q
def cyc_text(pp):
    cs = [c for c in pp.cyclic_form]
    return "".join("(" + " ".join(str(v + 1) for v in c) + ")" for c in sorted(cs, key=lambda c: min(c))) or "()"
case(A, "compute the product (1 2 3)(2 3 4)", ["eq", "product", cyc_text(prod)])
a = perm_from_cycles([[1, 3], [2, 4, 5]], 5)
case(A, "perm((1 3)(2 4 5))", ["eq", "order", str(a.order())], ["eq", "sign", str(a.signature())])
a = perm_from_cycles([[1, 2]], 3); b = perm_from_cycles([[1, 3]], 3)
case(A, "permcompose((1 2), (1 3))", ["eq", "product", cyc_text(b * a)])
case(A, "order of 4 in Z_10", ["eq", "order", str(10 // math.gcd(4, 10))])
case(A, "order of 3 mod 7", ["eq", "order", str(sp.n_order(3, 7))])
case(A, "order of 2 in (Z/11Z)*", ["eq", "order", str(sp.n_order(2, 11))])
case(A, "is U(8) cyclic", ["eq", "cyclic", "no"])
case(A, "is U(10) cyclic", ["eq", "cyclic", "yes"])
case(A, "primitive roots mod 13", ["set", "primitive roots", "{" + ", ".join(str(g) for g in range(1, 13) if sp.is_primitive_root(g, 13)) + "}"])
case(A, "find all generators of Z_12", ["set", "generators", "{1, 5, 7, 11}"])
case(A, "subgroups of Z_12", ["eq", "number of subgroups", str(len(sp.divisors(12)))])
case(A, "unitgroup(15)", ["eq", "group order", str(sp.totient(15))], ["eq", "cyclic", "no"])
case(A, "list all abelian groups of order 72", ["eq", "number of groups", "6"])
case(A, "how many abelian groups of order 360 are there", ["eq", "number of groups", str(3 * 2 * 1)])
case(A, "abeliangroups(16)", ["eq", "number of groups", "5"])
# finite fields
case(A, "in GF(7) compute 3/5", ["eq", "result", str(3 * pow(5, -1, 7) % 7)])
case(A, "inverse of 3 in GF(11)", ["eq", "result", str(pow(3, -1, 11))])
def gf_mul(a, b, p, m):
    X_ = sp.symbols("x"); return sp.Poly(sp.rem(sp.Poly(a, X_, modulus=p) * sp.Poly(b, X_, modulus=p), sp.Poly(m, X_, modulus=p)).as_expr(), X_, modulus=p)
def canon_gf(poly, p):
    X_ = sp.symbols("x"); cs = [int(c) % p for c in poly.all_coeffs()]
    return str(sp.Poly(cs, X_).as_expr())
X_ = sp.symbols("x")
case(A, "in GF(2^3) with modulus x^3 + x + 1 multiply x^2 + 1 and x^2 + x", ["eq", "result", canon_gf(gf_mul((X_**2 + 1), (X_**2 + X_), 2, X_**3 + X_ + 1), 2)])
inv = sp.invert(sp.Poly(X_**2 + 1, X_, modulus=2), sp.Poly(X_**3 + X_ + 1, X_, modulus=2))
case(A, "inverse of x^2 + 1 in GF(2)[x]/(x^3 + x + 1)", ["eq", "result", canon_gf(sp.Poly(inv, X_, modulus=2), 2)])
pw = sp.Poly(1, X_, modulus=2)
for _ in range(5): pw = sp.Poly(sp.rem(pw * sp.Poly(X_ + 1, X_, modulus=2), sp.Poly(X_**3 + X_ + 1, X_, modulus=2)).as_expr(), X_, modulus=2)
case(A, "gfcalc((x+1)^5, 2, x^3 + x + 1)", ["eq", "result", canon_gf(pw, 2)])
case(A, "in GF(9) = GF(3)[x]/(x^2 + 1) compute (x + 2)(2x + 1)", ["eq", "result", canon_gf(gf_mul(X_ + 2, 2 * X_ + 1, 3, X_**2 + 1), 3)])
def factor_text(f, p):
    fl = sp.factor_list(f, X_, modulus=p)
    parts = []
    for fac, e in fl[1]:
        cs = [int(c) % p for c in sp.Poly(fac, X_).all_coeffs()]
        lc = cs[0]; il = pow(lc, -1, p); cs = [c * il % p for c in cs]
        parts.append((len(cs) - 1, cs, e))
    parts.sort()
    return [f"{sp.Poly(cs, X_).as_expr()}" + (f" ^{e}" if e > 1 else "") for _, cs, e in parts]
def fac_case(inp, f, p):
    case(A, inp, ["eq", "irreducible factors", " ; ".join(factor_text(f, p))])
fac_case("factor x^4 + 1 over GF(3)", X_**4 + 1, 3)
fac_case("factormod(x^5 - x, 5)", X_**5 - X_, 5)
fac_case("factorise x^3 + x + 1 modulo 2", X_**3 + X_ + 1, 2)
fac_case("factor x^6 + x^5 + x^4 + x^3 + x^2 + x + 1 mod 2", sum(X_**i for i in range(7)), 2)
fac_case("factormod(x^4 + 4, 7)", X_**4 + 4, 7)
case(A, "is x^4 + x + 1 irreducible over GF(2)", ["eq", "irreducible", yn(sp.Poly(X_**4 + X_ + 1, X_, modulus=2).is_irreducible)])
case(A, "is x^2 + 1 irreducible over Z_3", ["eq", "irreducible", "yes"])
case(A, "irreducible(x^4 + x^2 + 1, 2)", ["eq", "irreducible", yn(sp.Poly(X_**4 + X_**2 + 1, X_, modulus=2).is_irreducible)])
case(A, "is x^3 - 2 irreducible over Q", ["eq", "irreducible", "yes"])
case(A, "is x^4 + 4 irreducible over Q", ["eq", "irreducible", "no"])
from sympy.polys.domains import ZZ_I
def gnorm(z):
    # associate in the first quadrant: re > 0, im >= 0
    a, b = int(z.x), int(z.y)
    for _ in range(4):
        if a > 0 and b >= 0: break
        a, b = -b, a
    return f"{a}+{b}*i" if b else str(a)
case(A, "gcd of 11 + 3i and 1 + 8i in the Gaussian integers", ["eq", "gcd", gnorm(ZZ_I.gcd(ZZ_I(11, 3), ZZ_I(1, 8)))])
case(A, "gaussgcd(4 + 7i, 1 + 3i)", ["eq", "gcd", gnorm(ZZ_I.gcd(ZZ_I(4, 7), ZZ_I(1, 3)))])
case(A, "gaussfactor(5)", ["eq", "norms", "5, 5"])
case(A, "factor 3 + 4i in Z[i]", ["eq", "norms", "5, 5"])
case(A, "is Z_2[x]/(x^2 + x + 1) a field", ["eq", "field", "yes"], ["eq", "number of elements", "4"])
case(A, "is Z_5[x]/(x^2 + 1) a field", ["eq", "field", "no"])
case(A, "quotientring(x^2 + 1)", ["eq", "field", "no"], ["eq", "integral domain", "yes"])

# ============================================================ 6. LP and game theory
A = "lp"
from scipy.optimize import linprog
def lp_opt(c, Aub, bub, maximize=True):
    r = linprog([-v for v in c] if maximize else c, A_ub=Aub, b_ub=bub, bounds=[(0, None)] * len(c), method="highs")
    return (-r.fun if maximize else r.fun), r.x, r.status
def lp_case(inp, c, Aub, bub, maximize=True):
    v, xs, st = lp_opt(c, Aub, bub, maximize)
    q = sp.nsimplify(round(v, 9), rational=True)
    case(A, inp, ["eq", "optimal value", fr(q)])
lp_case("maximize z = 3x + 5y subject to x <= 4, 2y <= 12, 3x + 2y <= 18, x >= 0, y >= 0", [3, 5], [[1, 0], [0, 2], [3, 2]], [4, 12, 18])
lp_case("lp(maximize 3x + 2y, x + y <= 4, x + 3y <= 6, x >= 0, y >= 0)", [3, 2], [[1, 1], [1, 3]], [4, 6])
lp_case("minimize 2x + 3y subject to x + y >= 4, x + 3y >= 6, x >= 0, y >= 0", [2, 3], [[-1, -1], [-1, -3]], [-4, -6], maximize=False)
lp_case("maximize 5x + 4y + 3z subject to 2x + 3y + z <= 5, 4x + y + 2z <= 11, 3x + 4y + 2z <= 8, x, y, z >= 0", [5, 4, 3], [[2, 3, 1], [4, 1, 2], [3, 4, 2]], [5, 11, 8])
lp_case("maximize x + y subject to x + 2y <= 7, 3x + y <= 9, x >= 0, y >= 0", [1, 1], [[1, 2], [3, 1]], [7, 9])
case(A, "maximize x + y subject to x - y <= 1, x >= 0, y >= 0", ["eq", "status", "unbounded"])
case(A, "maximize x + y subject to x + y <= 1, x + y >= 3, x >= 0, y >= 0", ["eq", "status", "infeasible"])
lp_case("minimize 3x + 2y subject to x + y >= 2, x <= 3, y <= 3, x >= 0, y >= 0", [3, 2], [[-1, -1], [1, 0], [0, 1]], [-2, 3, 3], maximize=False)
def ilp_brute(c, Aub, bub, box=30, maximize=True):
    best = None
    for pt in itertools.product(range(box + 1), repeat=len(c)):
        if all(sum(a * v for a, v in zip(row, pt)) <= b for row, b in zip(Aub, bub)):
            val = sum(a * v for a, v in zip(c, pt))
            if best is None or (val > best if maximize else val < best): best = val
    return best
case(A, "maximize 5x + 4y subject to 6x + 4y <= 24, x + 2y <= 6, x >= 0, y >= 0, x and y integers", ["eq", "optimal value", str(ilp_brute([5, 4], [[6, 4], [1, 2]], [24, 6]))])
case(A, "ilp(maximize 3x + 2y, 2x + 2y <= 9, 3x + y <= 11, x >= 0, y >= 0)", ["eq", "optimal value", str(ilp_brute([3, 2], [[2, 2], [3, 1]], [9, 11]))])
case(A, "integer programming: maximize x + y subject to 2x + 3y <= 12, 2x + y <= 6, x >= 0, y >= 0", ["eq", "optimal value", str(ilp_brute([1, 1], [[2, 3], [2, 1]], [12, 6]))])
def game_value(M):
    M = [[F(v) for v in r] for r in M]
    m, nn = len(M), len(M[0])
    # oracle: LP via scipy on shifted matrix
    shift = -min(min(r) for r in M) + 1
    Ms = [[float(v + shift) for v in r] for r in M]
    r = linprog([1] * m, A_ub=[[-Ms[i][j] for i in range(m)] for j in range(nn)], b_ub=[-1] * nn, bounds=[(0, None)] * m, method="highs")
    v = 1 / r.fun - shift
    return sp.nsimplify(round(v, 9), rational=True)
M = [[3, -1], [-2, 4]]; case(A, "value of the zero-sum game with payoff matrix [[3, -1], [-2, 4]]", ["eq", "value", fr(game_value(M))])
M = [[2, 3, 1], [4, 1, 2]]; case(A, "matrixgame([[2, 3, 1], [4, 1, 2]])", ["eq", "value", fr(game_value(M))])
M = [[1, -1], [-1, 1]]; case(A, "solve the matrix game [[1, -1], [-1, 1]]", ["eq", "value", "0"], ["eq", "row strategy", "(1/2, 1/2)"])
M = [[4, 2, 3], [1, 0, -1], [5, 1, 2]]; case(A, "matrixgame([[4, 2, 3], [1, 0, -1], [5, 1, 2]])", ["eq", "value", fr(game_value(M))])
M = [[0, -1, 1], [1, 0, -1], [-1, 1, 0]]; case(A, "value of rock paper scissors game [[0, -1, 1], [1, 0, -1], [-1, 1, 0]]", ["eq", "value", "0"])
def pure_ne(Am, Bm):
    out = []
    for i in range(len(Am)):
        for j in range(len(Am[0])):
            if Am[i][j] == max(Am[r][j] for r in range(len(Am))) and Bm[i][j] == max(Bm[i][c] for c in range(len(Am[0]))): out.append((i, j))
    return out
Am, Bm = [[3, 0], [5, 1]], [[3, 5], [0, 1]]
case(A, "nash([[3, 0], [5, 1]], [[3, 5], [0, 1]])", ["eq", "number of pure equilibria", str(len(pure_ne(Am, Bm)))], ["set", "pure equilibria", "{(R2, C2)}"])
Am, Bm = [[2, 0], [0, 1]], [[1, 0], [0, 2]]
case(A, "find the Nash equilibria of the bimatrix game A = [[2, 0], [0, 1]], B = [[1, 0], [0, 2]]", ["eq", "number of pure equilibria", "2"], ["eq", "mixed equilibrium", "row (2/3, 1/3), column (1/3, 2/3)"])
Am, Bm = [[1, -1], [-1, 1]], [[-1, 1], [1, -1]]
case(A, "nash equilibria of the game with A = [[1, -1], [-1, 1]] and B = [[-1, 1], [1, -1]]", ["eq", "number of pure equilibria", "0"], ["eq", "mixed equilibrium", "row (1/2, 1/2), column (1/2, 1/2)"])
Am, Bm = [[4, 1], [3, 2]], [[4, 3], [1, 2]]
case(A, "nash([[4, 1], [3, 2]], [[4, 3], [1, 2]])", ["eq", "number of pure equilibria", str(len(pure_ne(Am, Bm)))])

# ============================================================ 7. cryptography
A = "crypto"
p_, q_, e_ = 61, 53, 17
nn_, ph = p_ * q_, (p_ - 1) * (q_ - 1); d_ = pow(e_, -1, ph)
case(A, "rsa(p = 61, q = 53, e = 17)", ["eq", "n", str(nn_)], ["eq", "phi(n)", str(ph)], ["eq", "d", str(d_)])
case(A, "RSA with p = 61, q = 53, e = 17: encrypt m = 65", ["eq", "ciphertext", str(pow(65, e_, nn_))])
case(A, "decrypt c = 2790 with n = 3233 and d = 2753", ["eq", "plaintext", str(pow(2790, 2753, 3233))])
case(A, "RSA key generation with p = 11, q = 13, e = 7", ["eq", "d", str(pow(7, -1, 120))])
case(A, "rsa(p = 17, q = 11, e = 7, m = 88)", ["eq", "ciphertext", str(pow(88, 7, 187))])
case(A, "rsa(p = 61, q = 53, e = 12)", ["refuse"])
case(A, "compute 4^13 mod 497", ["eq", "result", str(pow(4, 13, 497))])
case(A, "modpow(123456789, 987654321, 1000000007)", ["eq", "result", str(pow(123456789, 987654321, 1000000007))])
case(A, "3^200 mod 13", ["eq", "result", str(pow(3, 200, 13))])
case(A, "inverse of 17 mod 3120", ["eq", "inverse", str(pow(17, -1, 3120))])
case(A, "multiplicative inverse of 3 modulo 11", ["eq", "inverse", str(pow(3, -1, 11))])
case(A, "modinverse(6, 9)", ["refuse"])
def dlog(g, h, p):
    for xx in range(p):
        if pow(g, xx, p) == h: return xx
case(A, "discrete log of 9 base 2 mod 11", ["eq", "x", str(dlog(2, 9, 11))])
case(A, "solve 3^x ≡ 13 (mod 17)", ["eq", "x", str(dlog(3, 13, 17))])
case(A, "dlog(5, 8, 23)", ["eq", "x", str(dlog(5, 8, 23))])
case(A, "dlog(2, 3, 7)", ["eq", "x", "none"])
case(A, "discrete logarithm of 17 to the base 3 modulo 1000003", ["eq", "x", str(dlog(3, 17, 1000003))])
case(A, "Diffie-Hellman with p = 23, g = 5, a = 6, b = 15", ["eq", "shared secret", str(pow(5, 6 * 15, 23))], ["eq", "A", str(pow(5, 6, 23))], ["eq", "B", str(pow(5, 15, 23))])
case(A, "diffiehellman(p = 97, g = 5, a = 36, b = 58)", ["eq", "shared secret", str(pow(5, 36 * 58, 97))])
case(A, "decrypt c = 2790 using CRT with p = 61, q = 53, d = 2753", ["eq", "plaintext", str(pow(2790, 2753, 3233))])
case(A, "rsacrt(c = 855, p = 61, q = 53, d = 2753)", ["eq", "plaintext", str(pow(855, 2753, 3233))])

# ============================================================ 8. topology
A = "topology"
def homology_oracle(facets):
    # independent oracle: ranks over Q plus torsion via sympy Smith normal form
    from sympy.matrices.normalforms import smith_normal_form
    simp = set()
    for f in facets:
        for r in range(1, len(f) + 1):
            for c in itertools.combinations(sorted(f), r): simp.add(c)
    by = {}
    for s in simp: by.setdefault(len(s) - 1, []).append(s)
    for d_ in by: by[d_].sort()
    top = max(by)
    idx = {d_: {s: i for i, s in enumerate(by[d_])} for d_ in by}
    def bd(d_):
        Mx = sp.zeros(len(by[d_ - 1]), len(by[d_]))
        for j, s in enumerate(by[d_]):
            for i in range(len(s)):
                face = s[:i] + s[i + 1:]
                Mx[idx[d_ - 1][face], j] = (-1) ** i
        return Mx
    ranks = {d_: (bd(d_).rank() if d_ >= 1 and d_ in by else 0) for d_ in range(0, top + 2)}
    betti = [len(by[d_]) - ranks[d_] - ranks.get(d_ + 1, 0) for d_ in range(top + 1)]
    chi = sum((-1) ** d_ * len(by[d_]) for d_ in by)
    tors = {}
    for d_ in range(1, top + 1):
        Mx = bd(d_)
        snf = smith_normal_form(Mx, domain=sp.ZZ)
        tors[d_ - 1] = [abs(int(snf[i, i])) for i in range(min(snf.shape)) if abs(int(snf[i, i])) > 1]
    return betti, chi, tors
def grp(b, t):
    parts = []
    if b: parts.append("Z" if b == 1 else f"Z^{b}")
    parts += [f"Z/{v}" for v in t]
    return " ⊕ ".join(parts) or "0"
TET = [(1, 2, 3), (1, 2, 4), (1, 3, 4), (2, 3, 4)]
b, c_, t_ = homology_oracle(TET)
case(A, "homology of the boundary of a tetrahedron", ["eq", "betti numbers", ", ".join(map(str, b))], ["eq", "euler characteristic", str(c_)])
case(A, "homology([1,2,3], [1,2,4], [1,3,4], [2,3,4])", ["eq", "H2", "Z"], ["eq", "H1", "0"])
case(A, "homology of the torus", ["eq", "betti numbers", "1, 2, 1"], ["eq", "H1", "Z^2"], ["eq", "euler characteristic", "0"])
case(A, "homology of the real projective plane", ["eq", "H1", "Z/2"], ["eq", "H2", "0"], ["eq", "euler characteristic", "1"])
case(A, "homology of the Klein bottle", ["eq", "H1", "Z ⊕ Z/2"], ["eq", "euler characteristic", "0"])
CIRC = [(1, 2), (2, 3), (1, 3)]
case(A, "betti numbers of the simplicial complex with facets {1,2}, {2,3}, {1,3}", ["eq", "betti numbers", "1, 1"])
CX = [(1, 2, 3), (3, 4), (4, 5), (5, 3), (6, 7)]
b, c_, t_ = homology_oracle(CX)
case(A, "homology([1,2,3], [3,4], [4,5], [5,3], [6,7])", ["eq", "betti numbers", ", ".join(map(str, b))], ["eq", "euler characteristic", str(c_)])
case(A, "euler characteristic of a polyhedron with 8 vertices, 12 edges and 6 faces", ["eq", "euler characteristic", "2"])
case(A, "eulerchar(V = 20, E = 30, F = 12)", ["eq", "euler characteristic", "2"])
OCT = [(1, 3, 5), (1, 3, 6), (1, 4, 5), (1, 4, 6), (2, 3, 5), (2, 3, 6), (2, 4, 5), (2, 4, 6)]
b, c_, t_ = homology_oracle(OCT)
case(A, "Betti numbers of the complex with triangles {1,3,5}, {1,3,6}, {1,4,5}, {1,4,6}, {2,3,5}, {2,3,6}, {2,4,5}, {2,4,6}", ["eq", "betti numbers", ", ".join(map(str, b))])
MOB = [(1, 2, 3), (2, 3, 4), (3, 4, 5), (1, 4, 5), (1, 2, 5)]
b, c_, t_ = homology_oracle(MOB)
case(A, "homology of the Mobius band", ["eq", "betti numbers", ", ".join(map(str, b))], ["eq", "H1", grp(b[1], t_.get(1, []))])
case(A, "homology of the 2-sphere", ["eq", "betti numbers", "1, 0, 1"])
SOLID = [(1, 2, 3, 4)]
case(A, "homology([1,2,3,4])", ["eq", "betti numbers", "1, 0, 0, 0"], ["eq", "euler characteristic", "1"])
case(A, "euler characteristic of the simplicial complex with facets {1,2,3}, {2,3,4}, {4,5}", ["eq", "euler characteristic", str(homology_oracle([(1, 2, 3), (2, 3, 4), (4, 5)])[1])])

# ============================================================ 9. proof-style requests
A = "proof"
case(A, "prove that n^3 - n is divisible by 6 for every integer n", ["eq", "status", "proved"], ["status", "exact"])
case(A, "prove that (a+b)^2 = a^2 + 2ab + b^2", ["eq", "status", "proved"])
case(A, "prove that the sum of the first n odd numbers is n^2", ["eq", "status", "proved"])
case(A, "prove that 1 + 2 + ... + n = n(n+1)/2", ["eq", "status", "proved"])
case(A, "prove that 2^n > n^2 for all n >= 5", ["eq", "status", "no counterexample found"], ["status", "evidence"])
case(A, "prove that n^2 + n + 41 is prime for all n >= 0", ["eq", "status", "disproved"], ["eq", "counterexample", "n = 40"])
case(A, "prove that there are infinitely many primes", ["refuse"])
case(A, "prove that sqrt(2) is irrational", ["refuse"])
case(A, "prove that p -> q is equivalent to not q -> not p", ["eq", "status", "proved"])
case(A, "prove that n^5 - n is divisible by 5 for all integers n", ["eq", "status", "proved"])
case(A, "prove that n^2 - n is divisible by 3 for all integers n", ["eq", "status", "disproved"])
case(A, "prove that (x - 1)(x + 1) = x^2 + 1", ["eq", "status", "disproved"])
case(A, "prove that the sum of k^3 for k = 1 to n is (n(n+1)/2)^2", ["eq", "status", "proved"])
case(A, "prove that every group of prime order is cyclic", ["refuse"])
case(A, "prove that 3^n > 2^n + n for all n >= 2", ["eq", "status", "no counterexample found"], ["status", "evidence"])
case(A, "prove that for all x in {1, 2, 3, 4, 5}, x^2 < 30", ["eq", "status", "proved"])
case(A, "prove that n! > 2^n for n >= 4", ["eq", "status", "no counterexample found"])
case(A, "prove that 6 divides n(n+1)(n+2) for all integers n", ["eq", "status", "proved"])

with open(OUT, "w") as fh:
    json.dump(CASES, fh, indent=1, ensure_ascii=False)
from collections import Counter
print(len(CASES), "cases", dict(Counter(c["area"] for c in CASES)))
