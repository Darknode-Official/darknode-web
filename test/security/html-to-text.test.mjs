// HTML to Text reads entities as the HTML Entity tool does, keeps <pre> as written and
// keeps the cells of a table row apart.
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as CODING } from "../../public/js/tools/coding.js";
import { TOOLS as ENC } from "../../public/js/tools/encoding.js";

const toText = (html) => CODING.find((t) => t.id === "cd-html-to-text").run({ html }, H);

group("quick tools: HTML to Text", () => {
  test("named entities beyond the basic eight are decoded", () => {
    assert.equal(toText("<p>Caf&eacute; &Eacute;t&eacute; &euro;5 &copy; &hellip;</p>"), "Café Été €5 © …\n");
  });
  test("<pre> keeps its line breaks and indentation", () => {
    assert.equal(toText("<p>Run:</p><pre>def f():\n    if x &lt; 1:\n        return 2\n</pre><p>after</p>"), "Run:\n\ndef f():\n    if x < 1:\n        return 2\n\nafter\n");
  });
  test("cells of a row are tab-separated, list items stay bulleted", () => {
    assert.equal(toText("<table><tr><td>a</td><td>b</td></tr><tr><th>c</th> <th>d</th></tr></table>"), "a\tb\n\nc\td\n");
    assert.equal(toText("<ul><li>one</li><li>two</li></ul>"), "- one\n\n- two\n");
  });
  test("the HTML Entity tool still decodes through the shared helper", () => {
    const t = ENC.find((x) => x.id === "html-entities" || /entit/i.test(x.name));
    assert.ok(/é/.test(t.run({ text: "&eacute;", input: "&eacute;", mode: "decode", op: "decode", dir: "decode" }, H)));
  });
});
