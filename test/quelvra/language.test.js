import { test, eq, ok } from "./harness.js";
import { translate, wordsToNumbers } from "../../public/quelvra/engine/language.js";
import { parse } from "../../public/quelvra/engine/parse.js";

const cases = [
  ["what is 15% of 80", "percent-of"], ["derivative of x^3 + 2x", "derivative"], ["find the derivative of sin(x) with respect to x", "derivative"],
  ["second derivative of x^4", "derivative"], ["integral of x^2 from 0 to 3", "integral-def"], ["integrate e^x", "integrate"],
  ["limit of sin(x)/x as x approaches 0", "limit"], ["limit of 1/x as x approaches 0 from the right", "limit"], ["limit of 1/x as x goes to infinity", "limit"],
  ["a number plus 7 is 19", "number-plus"], ["twice a number minus 3 is 11", "k-times-number"], ["3 times a number is 27", "k-times-number"],
  ["the sum of two numbers is 20 and their difference is 4", "sum-difference"], ["the sum of three consecutive integers is 72", "consecutive"],
  ["what is the square root of 144", "evaluate"], ["what is five squared plus three", "evaluate"], ["solve x^2 - 5x + 6 = 0", "solve"],
  ["solve a x + b = c for x", "solve-for"], ["simplify (x^2-1)/(x-1)", "simplify"], ["factor x^2 - 9", "simplify"], ["gcd of 12 and 18", "gcd"],
  ["is 97 prime", "is-prime"], ["mean of 3, 5, 7, 9", "mean"], ["what is the simple interest on $1000 at 5% per year for 3 years", "simple-interest"],
  ["find the prime factorization of 360", "prime-factor"], ["2x+3=11", "math"],
];
for (const [s, pat] of cases) test(`language: ${s}`, () => {
  const r = translate(s);
  ok(r.ok, `not understood: ${s} (${r.reason})`);
  eq(r.pattern, pat, s);
  parse(r.math); // must be parseable
});
test("refuses nonsense", () => ok(!translate("tell me a story about dragons").ok));
test("refuses vague", () => ok(!translate("what is the meaning of life").ok));
test("number words", () => eq(wordsToNumbers("three hundred and twenty five"), "325"));
test("fraction words", () => eq(wordsToNumbers("two thirds of x"), "(2/3) of x"));
test("sum-difference yields system", () => eq(parse(translate("the sum of two numbers is 20 and their difference is 4").math).k, "system"));
