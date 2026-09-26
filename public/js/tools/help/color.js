// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the color.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "col-hex-rgb": {
    what: "Type a color as a hex code (like #3276EA), an rgb() value or a color name, and get it back as rgb(red, green, blue) or as a #RRGGBB hex code, depending on the direction you pick.",
    when: "You have a color from a design file in one format and your code or tool needs it in the other.",
    example: { c: "#3276EA", mode: "HEX -> RGB" },
  },
  "col-hex-rgba": {
    what: "Converts a color with transparency between an 8-digit hex code (the last two digits are the opacity) and rgba(red, green, blue, alpha), where alpha runs from 0 (see-through) to 1 (solid).",
    when: "You need a semi-transparent color and your CSS or design tool expects it in the other notation.",
    example: { c: "#3276EA80", mode: "HEX -> RGBA" },
  },
  "col-rgb-hex": {
    what: "Type a color as rgb(50,118,234), as three numbers, or as a color name, and get the matching #RRGGBB hex code.",
    when: "You picked a color in a tool that shows red, green and blue numbers and need the short hex code for CSS or HTML.",
    example: { c: "rgb(50,118,234)" },
  },
  "col-rgb-hsl": {
    what: "Reads a color (hex, rgb() or a name) and gives it as hsl(hue, saturation, lightness), a format that describes the color by its shade, how vivid it is and how light it is. The other direction option returns the same color as rgb().",
    when: "You want a color in HSL so you can tweak its lightness or vividness by hand in CSS. To turn raw HSL numbers into RGB, use the HSL to RGB tool instead.",
    example: { c: "#3276EA", mode: "RGB -> HSL" },
  },
  "col-rgb-hsv": {
    what: "Reads a color (hex, rgb() or a name) and gives it as hsv(hue, saturation, value), the format many color pickers use, where value means brightness.",
    when: "You need to enter a color into a paint or photo program whose picker works in HSV (also called HSB).",
    example: { c: "rgb(50,118,234)" },
  },
  "col-rgb-cmyk": {
    what: "Reads a screen color (hex, rgb() or a name) and gives the cyan, magenta, yellow and black ink percentages used in printing.",
    when: "You are preparing a design for print and the printer asks for CMYK values. This is a simple formula, not a calibrated print profile, so real printed colors can differ.",
    example: { c: "#3276EA" },
  },
  "col-rgb-oklch": {
    what: "Reads a color and gives it as oklch(lightness chroma hue), a modern CSS color format where equal number changes look like equal changes to the human eye. Chroma means how colorful it is.",
    when: "You are building a CSS color scale and want steps that look evenly spaced, which oklch() makes easier than hex or HSL.",
    example: { c: "#3276EA" },
  },
  "col-rgb-oklab": {
    what: "Reads a color and gives it as oklab(lightness a b), a CSS color format built to match how people see color. The a and b numbers say how green-to-red and blue-to-yellow the color is.",
    when: "You want to blend or compare colors in a way that looks natural, or you need the oklab() value for modern CSS.",
    example: { c: "#3276EA" },
  },
  "col-rgb-xyz": {
    what: "Reads a color and gives its X, Y and Z values, a standard scientific description of color (CIE 1931, measured against daylight white). Y is the brightness part.",
    when: "You are doing color science or converting between color spaces and need the XYZ numbers as an in-between step.",
    example: { c: "#3276EA" },
  },
  "col-rgb-lab": {
    what: "Reads a color and gives it as lab(L a b), the CIELAB color space. L is lightness from 0 to 100, a runs green to red, and b runs blue to yellow.",
    when: "You need Lab values to compare colors, match paint or print colors, or feed a tool that measures color differences.",
    example: { c: "#3276EA" },
  },
  "col-hex-hsl": {
    what: "Type a hex color like #3276EA and get it as hsl(hue, saturation, lightness), which describes the color by its shade, how vivid it is and how light it is.",
    when: "You have a hex code from a brand guide and want the HSL version so you can make lighter or darker variants in CSS.",
    example: { c: "#3276EA" },
  },
  "col-hex-hsv": {
    what: "Type a hex color and get it as hsv(hue, saturation, value), where value means brightness. Many color pickers use this format.",
    when: "You need to type a hex color into a program whose color picker only takes HSV or HSB numbers.",
    example: { c: "#3276EA" },
  },
  "col-hex-cmyk": {
    what: "Type a hex color and get the cyan, magenta, yellow and black ink percentages for printing.",
    when: "You have a web color and a print shop wants CMYK values. It uses a simple formula, so check a real proof for exact color.",
    example: { c: "#3276EA" },
  },
  "col-hsl-hex": {
    what: "Type three HSL numbers (hue 0 to 360, saturation %, lightness %) separated by commas, and get the matching #RRGGBB hex code.",
    when: "You tuned a color in HSL and now need its hex code for a place that only accepts hex.",
    example: { t: "210, 80, 50" },
  },
  "col-hsv-hex": {
    what: "Type three HSV numbers (hue 0 to 360, saturation %, value or brightness %) separated by commas, and get the matching #RRGGBB hex code.",
    when: "You copied HSV or HSB numbers from a color picker and need the hex code for your website.",
    example: { t: "210, 79, 92" },
  },
  "col-name-hex": {
    what: "Type a CSS color name like cornflowerblue or crimson and get its hex code.",
    when: "You see a named color in someone's CSS and want to know its exact hex value. Only built-in CSS color names are known.",
    example: { t: "cornflowerblue" },
  },
  "col-hex-name": {
    what: "Type any color and get the CSS color name that is closest to it, plus that name's hex code. It tells you when the match is exact.",
    when: "You want a readable name for a color, for example to label it in a design system. The match is by simple red, green and blue distance, so it is approximate.",
    example: { c: "#6495ED" },
  },
  "col-luminance": {
    what: "Type a color and get its relative luminance, a number from 0 (black) to 1 (white) that says how bright it looks. This is the value accessibility (WCAG) contrast checks are based on.",
    when: "You are checking accessibility by hand or writing code that decides whether a color is dark or light.",
    example: { c: "#3276EA" },
  },
  "col-contrast": {
    what: "Type a text color and a background color and get their contrast ratio (like 12.63:1), plus PASS or fail for the WCAG AA and AAA accessibility levels for normal and large text.",
    when: "You want to make sure text on your website is readable for people with low vision before you ship a design.",
    example: { c: "#ffffff", c2: "#333333" },
  },
  "col-lighten": {
    what: "Type a color and an amount, and get a lighter version as a hex code. It raises the color's HSL lightness by that many percentage points.",
    when: "You need a lighter hover or background shade of your brand color without picking it by eye.",
    example: { c: "#3276EA", amt: "15" },
  },
  "col-darken": {
    what: "Type a color and an amount, and get a darker version as a hex code. It lowers the color's HSL lightness by that many percentage points.",
    when: "You need a darker shade of a button color for its pressed state or for a border.",
    example: { c: "#3276EA", amt: "15" },
  },
  "col-saturate": {
    what: "Type a color and an amount, and get a more vivid version as a hex code. It raises the color's HSL saturation by that many percentage points.",
    when: "Your color looks dull or washed out and you want a punchier version of the same shade.",
    example: { c: "#6b8cc4", amt: "20" },
  },
  "col-desaturate": {
    what: "Type a color and an amount, and get a more muted, grayer version as a hex code. It lowers the color's HSL saturation by that many percentage points.",
    when: "A color feels too loud and you want a calmer version for backgrounds or disabled states.",
    example: { c: "#3276EA", amt: "20" },
  },
  "col-grayscale": {
    what: "Type a color and get the gray that has the same perceived brightness, as a hex code.",
    when: "You want to see how a color will look in black and white, for example on a grayscale printout.",
    example: { c: "#3276EA" },
  },
  "col-invert": {
    what: "Type a color and get its opposite, like a photo negative, as a hex code. White becomes black and blue becomes orange-yellow.",
    when: "You need a quick high-difference color, or you are building an inverted or dark theme.",
    example: { c: "#3276EA" },
  },
  "col-mix": {
    what: "Type two colors and a percentage, and get the blended color as a hex code. 0% gives the first color, 100% gives the second, and 50% is halfway.",
    when: "You want a color that sits between two brand colors, for example for a chart series or a border.",
    example: { c: "#ff0000", c2: "#0000ff", amt: "50" },
  },
  "col-complementary": {
    what: "Type a color and get its complementary color, the one on the opposite side of the color wheel, as a hex code.",
    when: "You want an accent color that stands out strongly against your main color.",
    example: { c: "#3276EA" },
  },
  "col-analogous": {
    what: "Type a color and get three hex codes: a neighbor 30 degrees one way on the color wheel, your color, and a neighbor 30 degrees the other way.",
    when: "You want a calm, matching set of colors that sit next to each other on the color wheel.",
    example: { c: "#3276EA" },
  },
  "col-triadic": {
    what: "Type a color and get three hex codes spaced evenly around the color wheel (120 degrees apart), starting with your color.",
    when: "You need a balanced, colorful three-color scheme for a logo, chart or illustration.",
    example: { c: "#3276EA" },
  },
  "col-tetradic": {
    what: "Type a color and get four hex codes spaced 90 degrees apart on the color wheel, starting with your color.",
    when: "You need a rich four-color scheme, for example for chart categories. Usually one color should lead and the others act as accents.",
    example: { c: "#3276EA" },
  },
  "col-split-comp": {
    what: "Type a color and get three hex codes: your color plus the two colors on either side of its opposite on the color wheel (150 and 210 degrees away).",
    when: "You want strong contrast like a complementary pair but a little softer and easier to balance.",
    example: { c: "#3276EA" },
  },
  "col-monochromatic": {
    what: "Type a color and a number, and get that many hex codes of the same hue, going from very dark to very light.",
    when: "You are building a single-hue scale, such as blue-100 to blue-900, for a design system.",
    example: { c: "#3276EA", n: "6" },
  },
  "col-tints": {
    what: "Type a color and a number of steps, and get hex codes that go from your color to pure white by mixing in more white each step.",
    when: "You need soft, lighter versions of a color for backgrounds, highlights or hover states.",
    example: { c: "#3276EA", n: "6" },
  },
  "col-shades": {
    what: "Type a color and a number of steps, and get hex codes that go from your color to pure black by mixing in more black each step.",
    when: "You need darker versions of a color for text, borders or shadows that still match your palette.",
    example: { c: "#3276EA", n: "6" },
  },
  "col-linear-gradient": {
    what: "Type a start color, an end color and an angle, and get a ready-to-paste CSS line: background: linear-gradient(...).",
    when: "You want a straight color fade for a website banner or button and do not want to write the CSS by hand.",
    example: { c: "#3276EA", c2: "#ff00aa", ang: "90" },
  },
  "col-radial-gradient": {
    what: "Type a center color and an edge color, and get a ready-to-paste CSS line for a circular gradient that fades outward.",
    when: "You want a spotlight or glow effect behind a section of a web page.",
    example: { c: "#3276EA", c2: "#000000" },
  },
  "col-random-hex": {
    what: "Gives you one random color as a #RRGGBB hex code each time you run it. There is nothing to type.",
    when: "You need a quick placeholder color or some inspiration. The color is fully random, so it may be ugly or hard to read.",
    example: {},
  },
  "col-random-palette": {
    what: "Pick how many colors you want and get that many random hex codes.",
    when: "You want quick random colors for test charts, mock-ups or brainstorming. The colors are not chosen to match each other.",
    example: { n: "5" },
  },
  "col-css-rgb": {
    what: "Type a color in any supported form (hex, name or numbers) and get it written as a CSS rgb(red, green, blue) value.",
    when: "Your stylesheet uses rgb() everywhere and you want a color from somewhere else in the same style. Any transparency is dropped.",
    example: { c: "#3276EA" },
  },
  "col-css-hsl": {
    what: "Type a color in any supported form (hex, name or numbers) and get it written as a CSS hsl(hue, saturation%, lightness%) value, rounded to whole numbers.",
    when: "Your stylesheet uses hsl() so colors are easy to adjust, and you want to add a color given as hex.",
    example: { c: "coral" },
  },
  "col-alpha-composite": {
    what: "Type a foreground color, a background color and an opacity, and get the solid hex color you would see when the see-through foreground sits on top of the background.",
    when: "You need the actual on-screen color of a semi-transparent overlay, for example to check its contrast or to use a solid color instead.",
    example: { fg: "#ff0000", bg: "#ffffff", amt: "50" },
  },
  "col-hex8-rgba": {
    what: "Converts between an 8-digit hex code, where the last two digits are the opacity, and rgba(red, green, blue, alpha) with alpha from 0 to 1.",
    when: "A design tool gave you an 8-digit hex like #3276EAcc and your CSS or app needs rgba(), or the other way round.",
    example: { c: "#3276EAcc", mode: "HEX8 -> RGBA" },
  },
  "col-rotate-hue": {
    what: "Type a color and a number of degrees, and get a new hex color with the same vividness and lightness but a shifted hue (moved around the color wheel).",
    when: "You want a matching color in a different shade family, for example turning a blue theme into a purple or green one.",
    example: { c: "#3276EA", deg: "60" },
  },
  "col-web-safe": {
    what: "Type a color and get the closest of the 216 old web-safe colors, as a hex code. Each channel is rounded to 00, 33, 66, 99, CC or FF.",
    when: "You are working with a very limited display or an old system that only shows the web-safe palette.",
    example: { c: "#3276EA" },
  },
  "col-light-dark": {
    what: "Type a color and learn whether it looks Light or Dark, along with its perceived brightness on a scale of 0 to 255.",
    when: "You need to decide automatically whether text or icons on this color should be dark or light.",
    example: { c: "#3276EA" },
  },
  "col-best-text": {
    what: "Type a background color and find out whether black (#000000) or white (#ffffff) text is easier to read on it, with the contrast ratio.",
    when: "You are placing labels on colored buttons, tags or badges and want the most readable text color.",
    example: { c: "#3276EA" },
  },
  "col-kelvin-rgb": {
    what: "Pick a light color temperature in Kelvin and get the approximate matching hex color. Low numbers look warm orange (candles), high numbers look cool blue (overcast sky).",
    when: "You want to tint a scene, photo filter or smart-light preview to match real light, like 2700K bulbs or 6500K daylight. It is an approximation.",
    example: { amt: "3000" },
  },
  "col-blindness": {
    what: "Type a color and choose a type of color blindness, and get the hex color a person with that condition would roughly see.",
    when: "You want to check that the colors in your chart or interface can still be told apart by color-blind users. It is a rough simulation, not a medical test.",
    example: { c: "#e63946", mode: "Deuteranopia" },
  },
  "col-sepia": {
    what: "Type a color and get the old-photo brownish (sepia) version of it as a hex code.",
    when: "You are designing a vintage look and want to know what your colors become under a sepia filter.",
    example: { c: "#3276EA" },
  },
  "col-brightness": {
    what: "Type a color and a percentage, and get the color with every channel scaled by that amount. 100% leaves it unchanged, below 100% darkens it, above 100% brightens it.",
    when: "You want to predict what a CSS brightness() filter does to a color, or quickly make a brighter or dimmer variant.",
    example: { c: "#3276EA", amt: "120" },
  },
  "col-contrast-adjust": {
    what: "Type a color and a percentage, and get the color pushed away from (or toward) middle gray. 100% leaves it unchanged, higher values make it more extreme, lower values make it flatter.",
    when: "You want to predict what a CSS contrast() filter does to a single color.",
    example: { c: "#3276EA", amt: "150" },
  },
  "col-hue-rotate-filter": {
    what: "Type a color and a number of degrees, and get the CSS filter line hue-rotate(...) plus the hex color it produces, using the same math browsers use.",
    when: "You are applying a CSS hue-rotate filter to an icon or image and want to know the resulting color in advance.",
    example: { c: "#3276EA", deg: "90" },
  },
  "col-rgb-int": {
    what: "Type a color and get it as a single whole number (red, green and blue packed together), plus the same number written in hex with 0x.",
    when: "An API, game engine or Discord embed wants the color as one integer instead of a hex string.",
    example: { c: "#3276EA" },
  },
  "col-int-hex": {
    what: "Type a whole number from 0 to 16777215 (or a 0x hex number) and get the #RRGGBB color it represents.",
    when: "You found a color stored as a plain number in a database, config file or API response and want to see which color it is.",
    example: { t: "3307754" },
  },
  "col-hex-expand": {
    what: "Type a short 3- or 4-digit hex code like #abc and get the full form like #aabbcc, where every digit is doubled.",
    when: "A tool or file format only accepts full 6-digit (or 8-digit) hex codes and you have shorthand.",
    example: { t: "#3ae" },
  },
  "col-hex-validate": {
    what: "Type a hex code and find out whether it is a valid color. If it is, you get the clean lowercase #rrggbb form, plus the opacity when the code includes one.",
    when: "You are cleaning up colors from user input or a messy stylesheet and want them all in one consistent format.",
    example: { t: "#3276EA" },
  },
  "col-rgb-percent": {
    what: "Type three red, green and blue numbers and convert them between the 0 to 255 scale and the 0% to 100% scale.",
    when: "One program gives color channels as 0 to 255 and another wants percentages, or the other way round.",
    example: { t: "128, 64, 255", mode: "0-255 -> %" },
  },
  "col-hsl-rgb": {
    what: "Type three HSL numbers (hue 0 to 360, saturation %, lightness %) separated by commas, and get the color as rgb(red, green, blue).",
    when: "You have a color defined in HSL and a program that only accepts RGB numbers.",
    example: { t: "210, 80, 50" },
  },
  "col-hsv-rgb": {
    what: "Type three HSV numbers (hue 0 to 360, saturation %, value or brightness %) separated by commas, and get the color as rgb(red, green, blue).",
    when: "You copied HSV or HSB values from a photo editor and need the RGB numbers for code.",
    example: { t: "210, 79, 92" },
  },
  "col-cmyk-rgb": {
    what: "Type four CMYK ink percentages (cyan, magenta, yellow, black) separated by commas, and get the approximate screen color as a hex code.",
    when: "You have print color values from a brand guide and need a web color. It uses a simple formula, so it will not exactly match printed ink.",
    example: { t: "79, 50, 0, 8" },
  },
  "col-distance": {
    what: "Type two colors and get a number showing how different they are, measured as straight-line distance between their red, green and blue values. 0 means identical; about 441.67 is the maximum.",
    when: "You want a quick way to tell how close two colors are, for example to find near-duplicates in a palette. It does not match human perception perfectly.",
    example: { c: "#ff0000", c2: "#00ff00" },
  },
  "col-gradient-midpoint": {
    what: "Type two colors and get the color exactly halfway between them, as a hex code.",
    when: "You want a third color that bridges two others, for example the middle stop of a gradient.",
    example: { c: "#3276EA", c2: "#ff00aa" },
  },
  "col-scheme5": {
    what: "Type one base color and get five hex codes: your color, two neighbors on the color wheel, its opposite color, and a softer lighter version of that opposite as an accent.",
    when: "You are starting a website or app theme and want a quick, matching five-color palette from one brand color.",
    example: { c: "#3276EA" },
  },
  "col-hsl-hsv": {
    what: "Type three HSL numbers (hue, saturation %, lightness %) separated by commas and get the same color as hsv(hue, saturation, value).",
    when: "Your CSS uses HSL but a graphics program or color picker expects HSV or HSB.",
    example: { t: "210, 80, 50" },
  },
  "col-lum-sort": {
    what: "Paste a list of colors (hex, rgb() or names, one per line) and get them sorted from darkest to lightest, each with its brightness score.",
    when: "You are arranging a palette or picking which colors to use for dark and light parts of a design.",
    example: { text: "#3276EA\n#ff0000\nrgb(0,200,0)\n#222222\n#f5f5f5" },
  },
  "col-hsv-hsl": {
    what: "Type three HSV numbers (hue, saturation %, value %) separated by commas and get the same color as hsl(hue, saturation, lightness).",
    when: "You copied a color from a picker that uses HSV or HSB and your CSS needs hsl().",
    example: { t: "210, 79, 92" },
  },
  "col-average": {
    what: "Paste a list of colors (hex, rgb() or names) and get the single average color of all of them, as a hex code.",
    when: "You want one color that represents a group, for example the overall tone of a palette or of colors sampled from a photo.",
    example: { text: "#ff0000\n#00ff00\n#0000ff" },
  },
  "col-warm-cool": {
    what: "Type a color and find out whether it counts as Warm (reds, oranges, yellows), Cool (greens, blues) or Neutral (almost gray), with its hue in degrees.",
    when: "You are balancing the mood of a design and want to group colors by warm and cool. It uses a simple hue rule, so borderline colors can go either way.",
    example: { c: "#3276EA" },
  },
};
