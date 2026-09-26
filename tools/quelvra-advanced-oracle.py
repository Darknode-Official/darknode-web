#!/usr/bin/env python3
# Oracle for the Quelvra advanced-continuous probe corpus.
#
# sympy / mpmath are used HERE ONLY, offline, to build expected values for the tests. Nothing in
# this file is shipped or imported by the engine. Run:
#   python3 tools/quelvra-advanced-oracle.py > test/quelvra/advanced-continuous.corpus.js
#
# Each case: area, qs (inputs: call forms and plain-English phrasings; each one is a probe),
# want (the expected result in a small judge vocabulary understood by the test file).

import json, re
from fractions import Fraction
import sympy as sp
import mpmath as mp

mp.mp.dps = 40
x, y, z, t, s, n, w, r, th, u, v = sp.symbols("x y z t s n w r theta u v", real=True)
Z = sp.Symbol("z")  # complex variable for the complex-analysis cases


def q(e):
    """sympy expression -> Quelvra-parseable text"""
    e = sp.sympify(e)
    out = sp.sstr(e)
    out = out.replace("**", "^")
    out = re.sub(r"\bE\b", "e", out)
    out = re.sub(r"\bI\b", "i", out)
    out = re.sub(r"\bAbs\b", "abs", out)
    out = re.sub(r"\blog\b", "ln", out)
    out = re.sub(r"\bHeaviside\b", "heaviside", out)
    return out


CASES = []


def case(area, qs, want):
    if isinstance(qs, str):
        qs = [qs]
    CASES.append({"area": area, "qs": qs, "want": want})


def val(e):
    return {"value": q(sp.simplify(e))}


def vec(es):
    return {"vector": [q(sp.simplify(e)) for e in es]}


def mat(M):
    return {"matrix": [[q(sp.simplify(e)) for e in row] for row in M]}


def num(e, tol=1e-8):
    return {"approx": float(sp.N(e, 30)), "tol": tol}


REFUSE = {"refuse": True}

# ------------------------------------------------------------------ 1. multivariable calculus
A = "multivariable"
f = x**2 * y**3
case(A, ["pdiff(x^2*y^3, x, y)", "partial derivative of x^2 y^3 with respect to x and then y", "f_xy of x^2 y^3"], val(sp.diff(f, x, y)))
case(A, ["pdiff(sin(x*y), x, x)", "second partial derivative of sin(x y) with respect to x"], val(sp.diff(sp.sin(x * y), x, 2)))
case(A, ["pdiff(e^(x*y*z), x, y, z)"], val(sp.diff(sp.exp(x * y * z), x, y, z)))
case(A, ["pdiff(x^3*y^2 + y*z, y, y)", "f_yy for f = x^3 y^2 + y z"], val(sp.diff(x**3 * y**2 + y * z, y, 2)))
case(A, ["pdiff(ln(x^2 + y^2), x, y)"], val(sp.diff(sp.log(x**2 + y**2), x, y)))
case(A, ["f_xy for f(x, y) = x^3 y + e^(x y)", "pdiff(x^3*y + e^(x*y), x, y)"], val(sp.diff(x**3 * y + sp.exp(x * y), x, y)))
case(A, ["grad(x^2*y + y*z^2)", "gradient of x^2 y + y z^2"], vec([sp.diff(x**2 * y + y * z**2, V) for V in (x, y, z)]))
case(A, ["grad(x^2 + y^2, [x, y], [1, 2])", "gradient of x^2 + y^2 at (1, 2)"], vec([2, 4]))
case(A, ["grad(e^x*sin(y))", "grad of e^x sin(y)"], vec([sp.exp(x) * sp.sin(y), sp.exp(x) * sp.cos(y)]))
case(A, ["dirderiv(x^2*y, [3, 4], [1, 2])", "directional derivative of x^2 y at (1, 2) in the direction of (3, 4)"], val(sp.Rational(16, 5)))
case(A, ["dirderiv(x*y*z, [1, 1, 1], [1, 2, 3])", "directional derivative of x y z at (1, 2, 3) in the direction <1, 1, 1>"], val(sp.Rational(11) / sp.sqrt(3)))
case(A, ["dirderiv(x^2 + y^2, [1, 0])"], val(2 * x))
case(A, ["jacobian([x^2*y, x + y], [x, y])", "jacobian of (x^2 y, x + y)"], mat(sp.Matrix([x**2 * y, x + y]).jacobian([x, y]).tolist()))
case(A, ["jacobian([r*cos(theta), r*sin(theta)], [r, theta])"], mat(sp.Matrix([r * sp.cos(th), r * sp.sin(th)]).jacobian([r, th]).tolist()))
case(A, ["jacobiandet([r*cos(theta), r*sin(theta)], [r, theta])", "jacobian determinant of (r cos(theta), r sin(theta)) with respect to r and theta"], val(r))
case(A, ["jacobian([x*y*z, x + y + z, x*y], [x, y, z])"], mat(sp.Matrix([x * y * z, x + y + z, x * y]).jacobian([x, y, z]).tolist()))
case(A, ["hessian(x^3 + x*y^2)", "hessian of x^3 + x y^2", "hessian matrix of f(x, y) = x^3 + x y^2"], mat(sp.hessian(x**3 + x * y**2, (x, y)).tolist()))
case(A, ["hessian(x^2*y + y^3 - z^2)"], mat(sp.hessian(x**2 * y + y**3 - z**2, (x, y, z)).tolist()))
case(A, ["laplacian(x^2 + y^2 + z^2)", "laplacian of x^2 + y^2 + z^2"], val(6))
case(A, ["laplacian(e^x*sin(y))"], val(0))
case(A, ["laplacian(1/sqrt(x^2 + y^2 + z^2))"], val(0))
case(A, ["laplacian(x^3*y + y^3)"], val(sp.diff(x**3 * y + y**3, x, 2) + sp.diff(x**3 * y + y**3, y, 2)))
case(A, ["totaldiff(x^2*y)", "total differential of x^2 y"], {"differential": {"x": q(2 * x * y), "y": q(x**2)}})
case(A, ["totaldiff(x*y*z)"], {"differential": {"x": q(y * z), "y": q(x * z), "z": q(x * y)}})
case(A, ["tangentplane(x^2 + y^2, [1, 2])", "tangent plane to z = x^2 + y^2 at (1, 2)"], {"plane": "z = 2x + 4y - 5"})
case(A, ["tangentplane(x^2 + y^2 + z^2 = 14, [1, 2, 3])", "tangent plane to the surface x^2 + y^2 + z^2 = 14 at (1, 2, 3)"], {"plane": "x + 2y + 3z = 14"})
case(A, ["tangentplane(e^x*cos(y), [0, 0])", "equation of the tangent plane to z = e^x cos(y) at (0, 0)"], {"plane": "z = 1 + x"})
case(A, ["tangentplane(x*y, [2, 3])"], {"plane": "z = 3x + 2y - 6"})
case(A, ["critical(x^3 - 3x + y^2)", "critical points of x^3 - 3x + y^2", "classify the critical points of f(x, y) = x^3 - 3x + y^2"],
     {"points": [[{"x": "1", "y": "0"}, "min"], [{"x": "-1", "y": "0"}, "saddle"]]})
case(A, ["critical(x^2 + x*y + y^2 - 3x)", "local extrema of f(x, y) = x^2 + x y + y^2 - 3x"], {"points": [[{"x": "2", "y": "-1"}, "min"]]})
case(A, ["critical(x^3 + y^3 - 3x*y)", "find and classify the critical points of x^3 + y^3 - 3 x y"], {"points": [[{"x": "0", "y": "0"}, "saddle"], [{"x": "1", "y": "1"}, "min"]]})
case(A, ["critical(x^4 + y^4 - 4x*y + 1)"], {"points": [[{"x": "0", "y": "0"}, "saddle"], [{"x": "1", "y": "1"}, "min"], [{"x": "-1", "y": "-1"}, "min"]]})
case(A, ["critical(x^2 - y^2)", "saddle points of f(x, y) = x^2 - y^2"], {"points": [[{"x": "0", "y": "0"}, "saddle"]]})
case(A, ["critical(x*y*(1 - x - y))"], {"points": [[{"x": "0", "y": "0"}, "saddle"], [{"x": "1", "y": "0"}, "saddle"], [{"x": "0", "y": "1"}, "saddle"], [{"x": "1/3", "y": "1/3"}, "max"]]})
case(A, ["critical(x^4 + y^4)"], {"points": [[{"x": "0", "y": "0"}, "min|inconclusive"]]})
case(A, ["critical(2x^2 + y^2 + z^2 - 2x*z + 4)"], {"points": [[{"x": "0", "y": "0", "z": "0"}, "min"]]})
case(A, ["lagrange(x*y, x^2 + y^2 = 1)", "maximize x y subject to x^2 + y^2 = 1", "use lagrange multipliers to find the extreme values of x y subject to x^2 + y^2 = 1"], {"extrema": {"max": "1/2", "min": "-1/2"}})
case(A, ["lagrange(x + y, x^2 + y^2 = 2)", "extreme values of x + y subject to x^2 + y^2 = 2"], {"extrema": {"max": "2", "min": "-2"}})
case(A, ["lagrange(x^2 + y^2, x + y = 1)", "minimize x^2 + y^2 subject to x + y = 1"], {"candidates": [[{"x": "1/2", "y": "1/2"}, "1/2"]]})
case(A, ["lagrange(x + 2y + 3z, x^2 + y^2 + z^2 = 14)"], {"extrema": {"max": "14", "min": "-14"}})
case(A, ["find the extreme values of f(x, y) = x^2 + 2y^2 on the circle x^2 + y^2 = 1", "lagrange(x^2 + 2y^2, x^2 + y^2 = 1)"], {"extrema": {"max": "2", "min": "1"}})
case(A, ["lagrange(x*y*z, x^2 + y^2 + z^2 = 3)"], {"extrema": {"max": "1", "min": "-1"}})
case(A, ["dblint(x*y, x, 0, 1, y, 0, 2)", "double integral of x y over [0, 1] x [0, 2]", "integrate x y over the rectangle 0 <= x <= 1, 0 <= y <= 2"], val(1))
case(A, ["integrate(integrate(x^2 + y^2, x, 0, 1), y, 0, 1)"], val(sp.Rational(2, 3)))
case(A, ["dblint(x*y, y, 0, x, x, 0, 1)", "double integral of x y for y from 0 to x and x from 0 to 1"], val(sp.integrate(x * y, (y, 0, x), (x, 0, 1))))
case(A, ["dblint(e^(x + y), x, 0, 1, y, 0, 1)"], val(sp.integrate(sp.exp(x + y), (x, 0, 1), (y, 0, 1))))
case(A, ["dblint(sin(x)*cos(y), x, 0, pi, y, 0, pi/2)", "double integral of sin(x) cos(y) over [0, pi] x [0, pi/2]"], val(2))
case(A, ["dblint(x + y, y, x^2, x, x, 0, 1)"], val(sp.integrate(x + y, (y, x**2, x), (x, 0, 1))))
case(A, ["dblint(x^2*y, x, 0, 2, y, 1, 3)"], val(sp.integrate(x**2 * y, (x, 0, 2), (y, 1, 3))))
case(A, ["tplint(x*y*z, x, 0, 1, y, 0, 2, z, 0, 3)", "triple integral of x y z over the box [0, 1] x [0, 2] x [0, 3]"], val(sp.Rational(9, 2)))
case(A, ["tplint(1, z, 0, x + y, y, 0, 1, x, 0, 1)"], val(1))
case(A, ["tplint(x + y + z, x, 0, 1, y, 0, 1, z, 0, 1)"], val(sp.Rational(3, 2)))
case(A, ["polarint(x^2 + y^2, 0, 2, 0, 2pi)", "double integral of x^2 + y^2 over the disk x^2 + y^2 <= 4"], val(8 * sp.pi))
case(A, ["polarint(e^(-(x^2 + y^2)), 0, 1, 0, 2pi)", "integrate e^(-(x^2 + y^2)) over the unit disk using polar coordinates"], val(sp.pi * (1 - sp.exp(-1))))
case(A, ["polarint(1, 0, 2cos(theta), -pi/2, pi/2)"], val(sp.pi))
case(A, ["polarint(r, 0, 1, 0, pi)"], val(sp.pi / 3))
case(A, ["cylint(z, 0, 1, 0, 2pi, 0, 2)"], val(2 * sp.pi))
case(A, ["sphint(1, 0, 2, 0, 2pi, 0, pi)", "triple integral of 1 over the ball x^2 + y^2 + z^2 <= 4"], val(sp.Rational(32, 3) * sp.pi))
case(A, ["sphint(x^2 + y^2 + z^2, 0, 1, 0, 2pi, 0, pi)", "integrate x^2 + y^2 + z^2 over the unit ball in spherical coordinates"], val(sp.Rational(4, 5) * sp.pi))
case(A, ["critical(sin(x)*sin(y))"], REFUSE)

# ------------------------------------------------------------------ 2. vector calculus
A = "vector"
case(A, ["div([x^2, y*z, x*z])", "divergence of <x^2, y z, x z>"], val(3 * x + z))
case(A, ["div([x*y, y*z, z*x])", "div of (x y, y z, z x)"], val(x + y + z))
case(A, ["div([x, y])"], val(2))
case(A, ["div([x*e^y, y*e^z, z*e^x])"], val(sp.exp(y) + sp.exp(z) + sp.exp(x)))
case(A, ["curl([y, -x, 0])", "curl of (y, -x, 0)"], vec([0, 0, -2]))
case(A, ["curl([x*y, y*z, z*x])", "curl of F = <x y, y z, z x>"], vec([-y, -z, -x]))
case(A, ["curl([x^2, y^2, z^2])"], vec([0, 0, 0]))
case(A, ["curl([-y, x])"], val(2))
case(A, ["lineint([y, x], [t, t^2], t, 0, 1)", "line integral of F = <y, x> along r(t) = (t, t^2) for t from 0 to 1"], val(1))
case(A, ["lineint([-y, x], [cos(t), sin(t)], t, 0, 2pi)", "work done by F = (-y, x) along r(t) = (cos t, sin t) from t = 0 to 2pi"], val(2 * sp.pi))
case(A, ["lineint(x*y, [cos(t), sin(t)], t, 0, pi/2)", "line integral of x y ds along r(t) = (cos t, sin t) from t = 0 to pi/2"], val(sp.Rational(1, 2)))
case(A, ["lineint(x + y + z, [t, 2t, 3t], t, 0, 1)"], val(3 * sp.sqrt(14)))
case(A, ["lineint([y*z, x*z, x*y], [t, t^2, t^3], t, 0, 1)"], val(1))
case(A, ["lineint([x^2, x*y], [t, t], t, 0, 1)"], val(sp.Rational(2, 3)))
case(A, ["conservative([2*x*y, x^2])", "is F = <2 x y, x^2> conservative"], {"bool": True, "potential": q(x**2 * y)})
case(A, ["conservative([y, -x])", "is the vector field (y, -x) conservative"], {"bool": False})
case(A, ["potential([2*x*y + z^2, x^2, 2*x*z])", "find a potential function for F = (2 x y + z^2, x^2, 2 x z)"], {"potential": q(x**2 * y + x * z**2)})
case(A, ["potential([y*cos(x*y), x*cos(x*y)])"], {"potential": q(sp.sin(x * y))})
case(A, ["conservative([y*z, x*z, x*y])"], {"bool": True, "potential": q(x * y * z)})
case(A, ["potential([y, -x])"], REFUSE)
case(A, ["flux([x, y, z], [sin(u)*cos(v), sin(u)*sin(v), cos(u)], u, 0, pi, v, 0, 2pi)", "flux of F = <x, y, z> through the unit sphere"], val(4 * sp.pi))
case(A, ["flux of F = <x, y, z> through the sphere of radius 2"], val(32 * sp.pi))
case(A, ["flux([x, y, z], [u, v, 2], u, 0, 1, v, 0, 1)"], val(2))
case(A, ["surfint(1, [u*cos(v), u*sin(v), u], u, 0, 1, v, 0, 2pi)"], val(sp.pi * sp.sqrt(2)))
case(A, ["surfint(z^2, [sin(u)*cos(v), sin(u)*sin(v), cos(u)], u, 0, pi, v, 0, 2pi)", "surface integral of z^2 over the unit sphere"], val(4 * sp.pi / 3))

# ------------------------------------------------------------------ 3. transforms
A = "transforms"
def LT(f):
    return sp.laplace_transform(f, t, s, noconds=True)
case(A, ["laplace(t^2)", "laplace transform of t^2"], val(LT(t**2)))
case(A, ["laplace(e^(3t))", "laplace transform of e^(3t)"], val(LT(sp.exp(3 * t))))
case(A, ["laplace(sin(2t))", "find the laplace transform of sin(2t)"], val(LT(sp.sin(2 * t))))
case(A, ["laplace(t*e^(-t))"], val(LT(t * sp.exp(-t))))
case(A, ["laplace(e^(2t)*cos(3t))", "laplace transform of e^(2t) cos(3t)"], val(LT(sp.exp(2 * t) * sp.cos(3 * t))))
case(A, ["laplace(t*sin(t))"], val(LT(t * sp.sin(t))))
case(A, ["laplace(cosh(2t))"], val(LT(sp.cosh(2 * t))))
case(A, ["laplace(3 + 2t - e^(-t))"], val(LT(3 + 2 * t - sp.exp(-t))))
case(A, ["laplace(heaviside(t - 2))", "laplace transform of heaviside(t - 2)"], val(sp.exp(-2 * s) / s))
case(A, ["laplace(sin(t)^2)"], val(LT(sp.sin(t)**2)))
case(A, ["laplace(t^3*e^(2t))"], val(LT(t**3 * sp.exp(2 * t))))
case(A, ["laplace(e^(t^2))"], REFUSE)
def ILT(F):
    return sp.inverse_laplace_transform(F, s, t).subs(sp.Heaviside(t), 1)
case(A, ["invlaplace(1/(s^2 + 4))", "inverse laplace transform of 1/(s^2 + 4)"], val(ILT(1 / (s**2 + 4))))
case(A, ["invlaplace(1/(s*(s + 1)))", "inverse laplace of 1/(s(s + 1))"], val(ILT(1 / (s * (s + 1)))))
case(A, ["invlaplace((s + 1)/(s^2 + 2s + 5))"], val(ILT((s + 1) / (s**2 + 2 * s + 5))))
case(A, ["invlaplace(1/(s - 2)^3)"], val(ILT(1 / (s - 2)**3)))
case(A, ["invlaplace(5/(s^2 - 1))"], val(ILT(5 / (s**2 - 1))))
case(A, ["invlaplace((2s + 3)/(s^2 + 9))", "find the inverse laplace transform of (2s + 3)/(s^2 + 9)"], val(ILT((2 * s + 3) / (s**2 + 9))))
case(A, ["invlaplace(1/(s^2 + 1)^2)"], val(ILT(1 / (s**2 + 1)**2)))
case(A, ["invlaplace(e^(-s)/s^2)"], val((t - 1) * sp.Heaviside(t - 1)))
case(A, ["invlaplace(1/(s^3 + s))"], val(ILT(1 / (s**3 + s))))
case(A, ["invlaplace(ln(s))"], REFUSE)
tt = sp.Function("yy")
def ode(eq, ics):
    sol = sp.dsolve(eq, tt(t), ics=ics).rhs
    return val(sol)
Y = tt(t)
case(A, ["lapsolve(y'' + y = 0, y(0) = 1, y'(0) = 0)", "solve y'' + y = 0, y(0) = 1, y'(0) = 0 using laplace transforms"], ode(Y.diff(t, 2) + Y, {tt(0): 1, Y.diff(t).subs(t, 0): 0}))
case(A, ["lapsolve(y' + 2y = 4, y(0) = 1)", "use the laplace transform to solve y' + 2y = 4 with y(0) = 1"], ode(Y.diff(t) + 2 * Y - 4, {tt(0): 1}))
case(A, ["lapsolve(y'' + 3y' + 2y = e^t, y(0) = 1, y'(0) = 0)"], ode(Y.diff(t, 2) + 3 * Y.diff(t) + 2 * Y - sp.exp(t), {tt(0): 1, Y.diff(t).subs(t, 0): 0}))
case(A, ["lapsolve(y'' + 4y = sin(t), y(0) = 0, y'(0) = 0)"], ode(Y.diff(t, 2) + 4 * Y - sp.sin(t), {tt(0): 0, Y.diff(t).subs(t, 0): 0}))
case(A, ["lapsolve(y'' - 2y' + y = 0, y(0) = 0, y'(0) = 1)"], ode(Y.diff(t, 2) - 2 * Y.diff(t) + Y, {tt(0): 0, Y.diff(t).subs(t, 0): 1}))

def FS(fx, L, pw=None):
    k = sp.symbols("k", integer=True, positive=True)
    a0 = sp.integrate(fx, (x, -L, L)) / L if pw is None else sum(sp.integrate(e, (x, lo, hi)) for e, lo, hi in pw) / L
    def coef(trig):
        if pw is None:
            c = sp.integrate(fx * trig(k * sp.pi * x / L), (x, -L, L)) / L
        else:
            c = sum(sp.integrate(e * trig(k * sp.pi * x / L), (x, lo, hi)) for e, lo, hi in pw) / L
        c = sp.simplify(c)
        return q(c.subs(k, n))
    return {"fourier": {"a0": q(sp.simplify(a0)), "an": coef(sp.cos), "bn": coef(sp.sin)}}
case(A, ["fourier(x, x, pi)", "fourier series of x on [-pi, pi]"], FS(x, sp.pi))
case(A, ["fourier(x^2, x, pi)", "fourier series of f(x) = x^2 on -pi < x < pi"], FS(x**2, sp.pi))
case(A, ["fourier(abs(x), x, pi)", "fourier coefficients of |x| on [-pi, pi]"], FS(None, sp.pi, [(-x, -sp.pi, 0), (x, 0, sp.pi)]))
case(A, ["fourier(piecewise(-1, x < 0, 1, x >= 0), x, pi)"], FS(None, sp.pi, [(-1, -sp.pi, 0), (1, 0, sp.pi)]))
case(A, ["fourier(x, x, 1)", "fourier series of x on [-1, 1]"], FS(x, 1))
case(A, ["fourier(e^x, x, pi)"], FS(sp.exp(x), sp.pi))
case(A, ["fourier(x + x^2, x, pi)"], FS(x + x**2, sp.pi))

case(A, ["fouriertransform(e^(-abs(t)))", "fourier transform of e^(-|t|)"], val(2 / (1 + w**2)))
case(A, ["fouriertransform(e^(-t^2))", "fourier transform of e^(-t^2)"], val(sp.sqrt(sp.pi) * sp.exp(-w**2 / 4)))
case(A, ["fouriertransform(1/(1 + t^2))"], val(sp.pi * sp.exp(-sp.Abs(w))))
case(A, ["fouriertransform(piecewise(1, abs(t) <= 1, 0, abs(t) > 1))"], val(2 * sp.sin(w) / w))
case(A, ["fouriertransform(e^(-2*abs(t)))"], val(4 / (4 + w**2)))
case(A, ["fouriertransform(t)"], REFUSE)
N_ = sp.Symbol("n", integer=True, nonnegative=True)
def ZT(fn):
    return sp.simplify(sp.summation(fn * Z**(-N_), (N_, 0, sp.oo)).args[0][0]) if isinstance(sp.summation(fn * Z**(-N_), (N_, 0, sp.oo)), sp.Piecewise) else sp.simplify(sp.summation(fn * Z**(-N_), (N_, 0, sp.oo)))
def zval(e):
    return {"value": q(sp.simplify(e)), "vars": {"z": [2.5, 3.7, 5.2, -4.1, 6.3]}}
case(A, ["ztransform(2^n)", "z transform of 2^n"], zval(Z / (Z - 2)))
case(A, ["ztransform(n)", "z-transform of n"], zval(Z / (Z - 1)**2))
case(A, ["ztransform(1)"], zval(Z / (Z - 1)))
case(A, ["ztransform(n^2)"], zval(Z * (Z + 1) / (Z - 1)**3))
case(A, ["ztransform(cos(pi*n/2))"], zval(Z**2 / (Z**2 + 1)))
case(A, ["ztransform(n*3^n)"], zval(3 * Z / (Z - 3)**2))
case(A, ["ztransform((1/2)^n + n)"], zval(Z / (Z - sp.Rational(1, 2)) + Z / (Z - 1)**2))

# ------------------------------------------------------------------ 4. complex analysis
A = "complex"
def res(f, z0):
    return {"value": q(sp.nsimplify(sp.simplify(sp.residue(f, Z, z0)))), "complex": True}
case(A, ["residue(1/(z^2 + 1), z, i)", "residue of 1/(z^2 + 1) at z = i"], res(1 / (Z**2 + 1), sp.I))
case(A, ["residue(e^z/z^3, z, 0)", "residue of e^z/z^3 at z = 0"], res(sp.exp(Z) / Z**3, 0))
case(A, ["residue(1/(z*(z - 1)^2), z, 1)"], res(1 / (Z * (Z - 1)**2), 1))
case(A, ["residue(z/(z^2 - 3z + 2), z, 2)"], res(Z / (Z**2 - 3 * Z + 2), 2))
case(A, ["residue(sin(z)/z^4, z, 0)"], res(sp.sin(Z) / Z**4, 0))
case(A, ["residue(cos(z)/sin(z), z, 0)"], res(sp.cos(Z) / sp.sin(Z), 0))
case(A, ["residue(e^(2z)/(z - 1)^2, z, 1)", "find the residue of e^(2z)/(z - 1)^2 at z = 1"], res(sp.exp(2 * Z) / (Z - 1)**2, 1))
case(A, ["residue(1/(z^2 + 1), z)", "residues of 1/(z^2 + 1)"], {"residues": [["i", "-i/2"], ["-i", "i/2"]]})
def laur(expr_, n0, order):
    ser = sp.series(expr_, Z, n0, order).removeO()
    return {"laurent": q(ser)}
case(A, ["laurent(e^z/z^2, z, 0, 2)", "laurent series of e^z/z^2 about z = 0"], laur(sp.exp(Z) / Z**2, 0, 2))
case(A, ["laurent(1/(z*(z - 1)), z, 0, 2)"], laur(1 / (Z * (Z - 1)), 0, 2))
case(A, ["laurent(sin(z)/z^3, z, 0, 3)"], laur(sp.sin(Z) / Z**3, 0, 3))
case(A, ["laurent(1/(z^2 - 1), z, 1, 2)"], {"laurent": q(sp.series(1 / (Z**2 - 1), Z, 1, 2).removeO())})
case(A, ["contourint(1/z, z, 0, 1)", "integral of 1/z around |z| = 1", "contour integral of 1/z over the circle |z| = 1"], {"value": q(2 * sp.pi * sp.I), "complex": True})
case(A, ["contourint(1/(z^2 + 1), z, 0, 2)", "integral of 1/(z^2 + 1) around |z| = 2"], {"value": "0", "complex": True})
case(A, ["contourint(e^z/(z - 1), z, 0, 2)"], {"value": q(2 * sp.pi * sp.I * sp.E), "complex": True})
case(A, ["contourint(1/(z^2 + 1), z, i, 1)", "integral of 1/(z^2 + 1) around the circle |z - i| = 1"], {"value": q(sp.pi), "complex": True})
case(A, ["contourint(z^2/(z - 2)^2, z, 0, 3)"], {"value": q(8 * sp.pi * sp.I), "complex": True})
case(A, ["contourint(e^z/z^3, z, 0, 1)"], {"value": q(sp.pi * sp.I), "complex": True})
case(A, ["contourint(1/(z - 1), z, 0, 1)"], REFUSE)
def RI(f):
    return val(sp.integrate(f, (x, -sp.oo, sp.oo)))
case(A, ["residueint(1/(x^2 + 1))", "integral of 1/(x^2 + 1) from -infinity to infinity using residues"], RI(1 / (x**2 + 1)))
case(A, ["residueint(1/(x^4 + 1))", "evaluate the integral of 1/(x^4 + 1) from -infinity to infinity by residues"], RI(1 / (x**4 + 1)))
case(A, ["residueint(1/(x^2 + 4)^2)"], RI(1 / (x**2 + 4)**2))
case(A, ["residueint(cos(x)/(x^2 + 1))"], val(sp.pi / sp.E))
case(A, ["residueint(x^2/(x^4 + 1))"], RI(x**2 / (x**4 + 1)))
case(A, ["residueint(cos(2x)/(x^2 + 9))"], val(sp.pi * sp.exp(-6) / 3))
case(A, ["residueint(x/(x^2 + 1))"], REFUSE)
case(A, ["analytic(z^2)", "is f(z) = z^2 analytic"], {"bool": True})
case(A, ["analytic(conj(z))", "is conj(z) analytic"], {"bool": False})
case(A, ["cauchyriemann(x^2 - y^2, 2*x*y)", "check the cauchy-riemann equations for u = x^2 - y^2 and v = 2 x y"], {"bool": True})
case(A, ["analytic(e^z)"], {"bool": True})
case(A, ["cauchyriemann(x^2 + y^2, 2*x*y)"], {"bool": False, "where": "y = 0"})
case(A, ["analytic(abs(z)^2)"], {"bool": False, "where": "x = 0 and y = 0"})

# ------------------------------------------------------------------ 5. numerical methods
A = "numerical"
def root(fexpr, x0):
    fl = sp.lambdify(x, fexpr, "mpmath")
    return {"approx": float(mp.findroot(fl, x0)), "tol": 1e-8}
case(A, ["newton(x^3 - 2x - 5, x, 2)", "use newton's method to find a root of x^3 - 2x - 5 starting at x0 = 2"], root(x**3 - 2 * x - 5, 2))
case(A, ["newton(cos(x) - x, x, 1)", "newton's method for cos(x) = x with x0 = 1"], root(sp.cos(x) - x, 1))
case(A, ["newton(x^2 - 2, x, 1)"], root(x**2 - 2, 1))
case(A, ["use newton's method to solve e^x = 3x starting from x0 = 0", "newton(e^x - 3x, x, 0)"], root(sp.exp(x) - 3 * x, 0))
case(A, ["newton(x^2 - 4x + 4, x, 1)"], {"approx": 2.0, "tol": 1e-6})
case(A, ["bisection(x^3 - x - 2, x, 1, 2)", "use the bisection method to find a root of x^3 - x - 2 on [1, 2]"], root(x**3 - x - 2, 1.5))
case(A, ["bisection(cos(x) - x, x, 0, 1)"], root(sp.cos(x) - x, 0.7))
case(A, ["bisection(x^2 + 1, x, -1, 1)"], REFUSE)
case(A, ["secant(x^2 - 612, x, 10, 30)", "secant method for x^2 - 612 with x0 = 10 and x1 = 30"], root(x**2 - 612, 25))
case(A, ["secant(x^3 - x - 1, x, 1, 2)"], root(x**3 - x - 1, 1.3))
case(A, ["fixedpoint(cos(x), x, 1)", "fixed point iteration for x = cos(x) starting at x0 = 1"], root(sp.cos(x) - x, 0.7))
case(A, ["fixedpoint((x + 2/x)/2, x, 1)"], num(sp.sqrt(2)))
def trap(fexpr, a, b, N):
    h = (sp.Rational(b) - sp.Rational(a)) / N if not isinstance(b, sp.Basic) or b.is_Rational else (b - a) / N
    pts = [a + i * h for i in range(N + 1)]
    vals = [fexpr.subs(x, p) for p in pts]
    return h * (vals[0] / 2 + sum(vals[1:-1]) + vals[-1] / 2)
def simp(fexpr, a, b, N):
    h = (b - a) / sp.Integer(N)
    vals = [fexpr.subs(x, a + i * h) for i in range(N + 1)]
    return h / 3 * (vals[0] + vals[-1] + 4 * sum(vals[1:-1:2]) + 2 * sum(vals[2:-1:2]))
case(A, ["trapezoid(x^2, x, 0, 1, 4)", "trapezoidal rule for x^2 from 0 to 1 with n = 4"], num(trap(x**2, 0, 1, 4), 1e-12))
case(A, ["simpson(x^4, x, 0, 1, 4)", "simpson's rule for x^4 from 0 to 1 with n = 4"], num(simp(x**4, sp.Integer(0), sp.Integer(1), 4), 1e-12))
case(A, ["simpson(sin(x), x, 0, pi, 6)"], num(simp(sp.sin(x), sp.Integer(0), sp.pi, 6), 1e-12))
case(A, ["trapezoid(e^x, x, 0, 1, 10)"], num(simp(sp.exp(x), 0, 1, 10) * 0 + trap(sp.exp(x), sp.Integer(0), sp.Integer(1), 10), 1e-12))
case(A, ["use simpson's rule with n = 4 to approximate the integral of 1/(1 + x^2) from 0 to 1", "simpson(1/(1 + x^2), x, 0, 1, 4)"], num(simp(1 / (1 + x**2), sp.Integer(0), sp.Integer(1), 4), 1e-12))
def euler(fexpr, xv, yv, x0, y0, h, x1, rk=False):
    X_, Y_ = Fraction(x0), Fraction(y0)
    H = Fraction(h)
    steps = round((Fraction(x1) - X_) / H)
    F = lambda a, b: sp.Rational(fexpr.subs({xv: sp.Rational(a.numerator, a.denominator), yv: sp.Rational(b.numerator, b.denominator)})) if False else fexpr.subs({xv: a, yv: b})
    Xs, Ys = sp.Rational(X_.numerator, X_.denominator), sp.Rational(Y_.numerator, Y_.denominator)
    Hs = sp.Rational(H.numerator, H.denominator)
    for _ in range(steps):
        if rk:
            k1 = fexpr.subs({xv: Xs, yv: Ys})
            k2 = fexpr.subs({xv: Xs + Hs / 2, yv: Ys + Hs * k1 / 2})
            k3 = fexpr.subs({xv: Xs + Hs / 2, yv: Ys + Hs * k2 / 2})
            k4 = fexpr.subs({xv: Xs + Hs, yv: Ys + Hs * k3})
            Ys = Ys + Hs / 6 * (k1 + 2 * k2 + 2 * k3 + k4)
        else:
            Ys = Ys + Hs * fexpr.subs({xv: Xs, yv: Ys})
        Xs = Xs + Hs
    return num(Ys, 1e-10)
case(A, ["eulermethod(x + y, x, y, 0, 1, 0.1, 1)", "use euler's method with h = 0.1 to approximate y(1) for y' = x + y, y(0) = 1"], euler(x + y, x, y, 0, 1, "0.1", 1))
case(A, ["eulermethod(y, t, y, 0, 1, 0.25, 1)"], euler(y, t, y, 0, 1, "0.25", 1))
case(A, ["rungekutta(x + y, x, y, 0, 1, 0.1, 1)", "use rk4 with h = 0.1 to approximate y(1) where y' = x + y and y(0) = 1"], euler(x + y, x, y, 0, 1, "0.1", 1, True))
case(A, ["rungekutta(-2*t*y, t, y, 0, 1, 0.1, 1)"], euler(-2 * t * y, t, y, 0, 1, "0.1", 1, True))
case(A, ["use euler's method with step size 0.1 to approximate y(0.5) where y' = x^2 + y, y(0) = 1", "eulermethod(x^2 + y, x, y, 0, 1, 0.1, 0.5)"], euler(x**2 + y, x, y, 0, 1, "0.1", "0.5"))
case(A, ["poweriter([[2, 1], [1, 3]])", "power method for the matrix [[2, 1], [1, 3]]"], num((5 + sp.sqrt(5)) / 2, 1e-8))
case(A, ["poweriter([[4, 1], [2, 3]])"], num(5, 1e-8))
case(A, ["poweriter([[2, 0, 0], [0, 3, 4], [0, 4, 9]])"], num(11, 1e-8))

# ------------------------------------------------------------------ 6. curves
A = "curves"
case(A, ["curvature([cos(t), sin(t), t], t)", "curvature of r(t) = (cos t, sin t, t)"], val(sp.Rational(1, 2)))
case(A, ["curvature(x^2, x, 1)", "curvature of y = x^2 at x = 1"], val(2 / (5 * sp.sqrt(5))))
case(A, ["curvature([t, t^2], t, 0)"], val(2))
case(A, ["curvature([3cos(t), 3sin(t)], t)", "curvature of the circle r(t) = (3 cos t, 3 sin t)"], val(sp.Rational(1, 3)))
case(A, ["curvature(sin(x), x, pi/2)"], val(1))
case(A, ["curvature([t, t^2, t^3], t, 0)"], val(2))
case(A, ["curvature(ln(x), x, 1)"], val(sp.sqrt(2) / 4))
case(A, ["curvature(x^3, x)"], val(sp.Abs(6 * x) / (1 + 9 * x**4)**sp.Rational(3, 2)))
case(A, ["torsion([cos(t), sin(t), t], t)", "torsion of r(t) = (cos t, sin t, t)"], val(sp.Rational(1, 2)))
case(A, ["torsion([t, t^2, t^3], t, 0)"], val(3))
case(A, ["torsion([t, t^2, 0], t)"], val(0))
case(A, ["unittangent([cos(t), sin(t), t], t)", "unit tangent vector of r(t) = (cos t, sin t, t)"], vec([-sp.sin(t) / sp.sqrt(2), sp.cos(t) / sp.sqrt(2), 1 / sp.sqrt(2)]))
case(A, ["unitnormal([cos(t), sin(t), t], t)", "principal unit normal of r(t) = (cos t, sin t, t)"], vec([-sp.cos(t), -sp.sin(t), 0]))
case(A, ["binormal([cos(t), sin(t), t], t)", "binormal vector of r(t) = (cos t, sin t, t)"], vec([sp.sin(t) / sp.sqrt(2), -sp.cos(t) / sp.sqrt(2), 1 / sp.sqrt(2)]))
case(A, ["unittangent([t, t^2], t, 1)"], vec([1 / sp.sqrt(5), 2 / sp.sqrt(5)]))
case(A, ["arclength([cos(t), sin(t), t], t, 0, 2pi)", "arc length of r(t) = (cos t, sin t, t) from t = 0 to 2pi"], val(2 * sp.sqrt(2) * sp.pi))
case(A, ["arclength([t^2, t^3], t, 0, 1)"], val((13 * sp.sqrt(13) - 8) / 27))
case(A, ["arcparam([3cos(t), 3sin(t), 4t], t)", "arc length parametrization of r(t) = (3 cos t, 3 sin t, 4t)"], {"vector": [q(3 * sp.cos(sp.Symbol("s") / 5)), q(3 * sp.sin(sp.Symbol("s") / 5)), q(4 * sp.Symbol("s") / 5)], "label": "r(s)"})
case(A, ["arcparam([t, t], t)"], {"vector": [q(sp.Symbol("s") / sp.sqrt(2)), q(sp.Symbol("s") / sp.sqrt(2))], "label": "r(s)"})

# ------------------------------------------------------------------ 7. PDE
A = "pde"
case(A, ["pdecheck(e^(-t)*sin(x), u_t = u_xx)", "verify that u = e^(-t) sin(x) satisfies u_t = u_xx"], {"bool": True})
case(A, ["pdecheck(sin(x - 2t), u_tt = 4u_xx)", "does u = sin(x - 2t) satisfy u_tt = 4 u_xx"], {"bool": True})
case(A, ["pdecheck(x^2 - y^2, u_xx + u_yy = 0)", "show that u = x^2 - y^2 satisfies u_xx + u_yy = 0"], {"bool": True})
case(A, ["pdecheck(x^2 + y^2, u_xx + u_yy = 0)"], {"bool": False})
case(A, ["pdecheck(e^(-4t)*sin(2x), u_t = u_xx)"], {"bool": True})
case(A, ["pdecheck(e^(-t)*sin(x), u_t = 2u_xx)"], {"bool": False})
case(A, ["classifypde(u_xx + 2u_xy + u_yy = 0)", "classify the pde u_xx + 2 u_xy + u_yy = 0"], {"type": "parabolic"})
case(A, ["classifypde(u_xx - 4u_yy = 0)", "classify u_xx - 4 u_yy = 0"], {"type": "hyperbolic"})
case(A, ["classifypde(u_xx + u_yy = 0)"], {"type": "elliptic"})
case(A, ["classifypde(3u_xx + 2u_xy + 5u_yy + u_x = 0)"], {"type": "elliptic"})
case(A, ["classifypde(u_xx + x*u_yy = 0)", "classify the pde u_xx + x u_yy = 0"], {"regions": {"elliptic": "x > 0", "hyperbolic": "x < 0", "parabolic": "x = 0"}})
case(A, ["heat(sin(pi*x), x, t, 1, 1)", "solve the heat equation u_t = u_xx on 0 < x < 1 with u(0, t) = u(1, t) = 0 and u(x, 0) = sin(pi x)"], {"value": q(sp.exp(-sp.pi**2 * t) * sp.sin(sp.pi * x)), "label": "u(x, t)"})
def bn(fx, L):
    k = sp.symbols("k", integer=True, positive=True)
    return q(sp.simplify(sp.Integer(2) / L * sp.integrate(fx * sp.sin(k * sp.pi * x / L), (x, 0, L))).subs(k, n))
case(A, ["heat(x*(1 - x), x, t, 1, 1)", "heat equation u_t = u_xx on [0, 1] with zero boundary conditions and u(x, 0) = x(1 - x)"], {"bn": bn(x * (1 - x), 1)})
case(A, ["heat(1, x, t, pi, 1)"], {"bn": bn(sp.Integer(1), sp.pi)})
case(A, ["heat(x, x, t, 2, 3)"], {"bn": bn(x, 2)})
case(A, ["wave(sin(pi*x), 0, x, t, 1, 1)", "solve the wave equation u_tt = u_xx on 0 < x < 1 with u(0, t) = u(1, t) = 0, u(x, 0) = sin(pi x) and u_t(x, 0) = 0"], {"value": q(sp.sin(sp.pi * x) * sp.cos(sp.pi * t)), "label": "u(x, t)"})
case(A, ["wave(0, sin(pi*x), x, t, 1, 2)"], {"value": q(sp.sin(sp.pi * x) * sp.sin(2 * sp.pi * t) / (2 * sp.pi)), "label": "u(x, t)"})
case(A, ["wave(x*(1 - x), 0, x, t, 1, 1)"], {"an": bn(x * (1 - x), 1)})

total = sum(len(c["qs"]) for c in CASES)
print("// Generated by tools/quelvra-advanced-oracle.py (sympy/mpmath as an OFFLINE oracle only). Do not edit by hand.")
print(f"// {len(CASES)} cases, {total} probes.")
print("export const CORPUS = " + json.dumps(CASES, indent=1) + ";")
