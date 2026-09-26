// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the mathx.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "mx-base-convert": {
    what: "Converts a whole number from one number base to another, from base 2 (binary) up to base 36, for example hex ff to decimal 255.",
    when: "You need to translate a number between number systems for programming, puzzles or homework.",
    example: { n: "ff", from: "16", to: "10" },
  },
  "mx-bin-convert": {
    what: "Turns a normal (decimal) whole number into binary, the 0s and 1s computers use, or turns binary back into decimal.",
    when: "You are learning binary or reading bit values in code or hardware docs.",
    example: { n: "42", dir: "d2b" },
  },
  "mx-hex-convert": {
    what: "Turns a normal (decimal) whole number into hexadecimal (base 16, digits 0-9 and a-f), or hex back into decimal. A leading 0x is allowed.",
    when: "You see a hex value like 0x1F4 in code, colors or memory addresses and want the normal number.",
    example: { n: "0x1F4", dir: "h2d" },
  },
  "mx-oct-convert": {
    what: "Turns a normal (decimal) whole number into octal (base 8), or octal back into decimal.",
    when: "You are working with octal values such as Unix file permissions or older data formats.",
    example: { n: "493", dir: "d2o" },
  },
  "mx-bitwise-and": {
    what: "Combines two whole numbers bit by bit with AND: a bit is 1 in the result only if it is 1 in both numbers. The answer is shown as a decimal number.",
    when: "You are checking flags or masks in code, for example whether a permission bit is set.",
    example: { a: "12", b: "10" },
  },
  "mx-bitwise-or": {
    what: "Combines two whole numbers bit by bit with OR: a bit is 1 in the result if it is 1 in either number. The answer is shown as a decimal number.",
    when: "You want to see the value you get when you switch on several flags together.",
    example: { a: "12", b: "10" },
  },
  "mx-bitwise-xor": {
    what: "Combines two whole numbers bit by bit with XOR: a bit is 1 in the result only when the two numbers differ at that bit. The answer is shown as a decimal number.",
    when: "You are toggling flags, comparing bit patterns, or checking a simple XOR checksum.",
    example: { a: "12", b: "10" },
  },
  "mx-bitwise-not": {
    what: "Flips every bit of a whole number (1s become 0s and 0s become 1s), treating it as a 32-bit value like JavaScript does.",
    when: "You want to know what ~x gives in code, for example when building a mask to clear bits.",
    example: { a: "5" },
  },
  "mx-left-shift": {
    what: "Moves all the bits of a number to the left by a set amount, which is like multiplying by 2 for each step (within 32 bits).",
    when: "You want to check what a << b gives in code, for example when building bit flags.",
    example: { a: "3", b: "4" },
  },
  "mx-right-shift": {
    what: "Moves all the bits of a number to the right by a set amount, which is like dividing by 2 for each step and rounding down. Negative numbers stay negative.",
    when: "You want to check what a >> b gives in code for a signed 32-bit number.",
    example: { a: "-64", b: "2" },
  },
  "mx-unsigned-right-shift": {
    what: "Moves all the bits of a number to the right and fills with zeros, so the result is never negative (JavaScript's >>> operator).",
    when: "You need to see how a negative number looks as an unsigned 32-bit value after a shift.",
    example: { a: "-64", b: "2" },
  },
  "mx-twos-complement": {
    what: "Shows how a whole number, including negative ones, is stored in binary using two's complement (the usual way computers store negative numbers) at the bit width you choose.",
    when: "You are learning how negative numbers are stored, or decoding signed bytes in a file or network packet.",
    example: { n: "-5", bits: "8" },
  },
  "mx-popcount": {
    what: "Counts how many 1 bits there are in the binary form of a non-negative whole number.",
    when: "You are working with bit masks or sets stored as bits and need to know how many are switched on.",
    example: { n: "255" },
  },
  "mx-float-bits": {
    what: "Shows how a decimal number is really stored in a computer as a floating-point value: the sign, exponent and fraction bits, in 32-bit or 64-bit form.",
    when: "You are curious why 0.1 + 0.2 is not exactly 0.3, or you are decoding float values from binary data.",
    example: { x: "0.1", prec: "32" },
  },
  "mx-gcd": {
    what: "Finds the greatest common divisor, the biggest whole number that divides all of your numbers evenly. Separate numbers with commas, spaces or new lines.",
    when: "You want to simplify a fraction or split things into the largest equal groups.",
    example: { nums: "48, 180, 36" },
  },
  "mx-lcm": {
    what: "Finds the least common multiple, the smallest number that all of your numbers divide into evenly. Separate numbers with commas, spaces or new lines.",
    when: "You need a common denominator, or want to know when repeating schedules will line up again.",
    example: { nums: "4, 6, 10" },
  },
  "mx-is-prime": {
    what: "Tells you whether a whole number is prime, meaning only 1 and itself divide it evenly.",
    when: "You are checking a number for homework, a puzzle, or a programming task.",
    example: { n: "97" },
  },
  "mx-prime-factorization": {
    what: "Breaks a whole number greater than 1 into the prime numbers that multiply together to make it, for example 360 = 2^3 x 3^2 x 5.",
    when: "You need prime factors to simplify fractions, find GCD or LCM by hand, or check homework.",
    example: { n: "360" },
  },
  "mx-next-prime": {
    what: "Finds the smallest prime number that is bigger than the number you enter.",
    when: "You need a prime just above a certain size, for example for a hash table size.",
    example: { n: "100" },
  },
  "mx-primes-up-to": {
    what: "Lists every prime number from 2 up to the limit you enter.",
    when: "You want a quick list of primes for study, testing or a puzzle.",
    example: { n: "50" },
  },
  "mx-nth-prime": {
    what: "Gives the prime number at a given position in the list of primes, where the 1st prime is 2, the 2nd is 3, and so on.",
    when: "You need, for example, the 100th prime for a puzzle or test.",
    example: { n: "100" },
  },
  "mx-is-perfect": {
    what: "Tells you whether a number is perfect, meaning it equals the sum of its divisors other than itself (6 = 1 + 2 + 3).",
    when: "You are exploring number puzzles or checking a maths exercise.",
    example: { n: "28" },
  },
  "mx-is-armstrong": {
    what: "Tells you whether a number is an Armstrong number: each digit raised to the power of the number of digits adds up to the number itself (153 = 1^3 + 5^3 + 3^3).",
    when: "You are solving a classic programming exercise or number puzzle.",
    example: { n: "153" },
  },
  "mx-is-palindrome-number": {
    what: "Tells you whether a whole number reads the same forwards and backwards, like 12321.",
    when: "You are checking an answer for a puzzle or a coding exercise.",
    example: { n: "12321" },
  },
  "mx-mod-exp": {
    what: "Calculates a to the power b, then the remainder after dividing by m, quickly even for very large numbers.",
    when: "You are studying cryptography like RSA or solving number theory problems where the full power would be huge.",
    example: { a: "4", b: "13", m: "497" },
  },
  "mx-mod-inverse": {
    what: "Finds the number x that, multiplied by a, leaves a remainder of 1 when divided by m. It tells you if no such number exists.",
    when: "You are working through RSA key maths or modular arithmetic homework.",
    example: { a: "3", m: "11" },
  },
  "mx-roman-to-int": {
    what: "Turns a Roman numeral like MMXXVI into a normal number.",
    when: "You see a Roman numeral on a building, film credits or a clock and want its value.",
    example: { s: "MCMXCIV" },
  },
  "mx-int-to-roman": {
    what: "Turns a normal number from 1 to 3999 into Roman numerals.",
    when: "You need a Roman numeral for a chapter heading, an event name or a design.",
    example: { n: "2026" },
  },
  "mx-percentage-of": {
    what: "Works out a percentage of a number, for example 15% of 80 is 12.",
    when: "You are calculating a tip, discount or tax amount.",
    example: { p: "15", n: "80" },
  },
  "mx-what-percent": {
    what: "Tells you what percentage one number is of another, for example 30 is 25% of 120.",
    when: "You want to know your score as a percentage, or what share of a total one part is.",
    example: { a: "30", b: "120" },
  },
  "mx-percentage-change": {
    what: "Tells you by what percentage a value went up or down, from an old value to a new one.",
    when: "You are comparing prices, sales or scores between two periods. The old value cannot be zero.",
    example: { old: "80", new: "100" },
  },
  "mx-increase-decrease-percent": {
    what: "Adds or takes away a percentage from a value, for example 200 increased by 15% is 230.",
    when: "You are applying a price rise, a discount or tax to an amount.",
    example: { n: "200", p: "15", mode: "dec" },
  },
  "mx-ratio-simplify": {
    what: "Reduces a ratio like 1920:1080 to its simplest form, like 16:9.",
    when: "You want the aspect ratio of a screen or image, or to simplify a recipe or mix ratio.",
    example: { a: "1920", b: "1080" },
  },
  "mx-fraction-to-decimal": {
    what: "Turns a fraction written like 3/8 into a decimal number.",
    when: "You have a measurement or answer as a fraction and need it as a decimal.",
    example: { s: "3/8" },
  },
  "mx-decimal-to-fraction": {
    what: "Finds a simple fraction that equals, or is very close to, a decimal number, for example 0.375 becomes 3/8.",
    when: "You have a decimal like 0.3333 and want the fraction it most likely stands for.",
    example: { x: "0.375" },
  },
  "mx-scientific-notation": {
    what: "Turns a normal number into scientific notation (like 1.5e+3 for 1500), or turns scientific notation back into a normal number.",
    when: "You are dealing with very large or very small numbers from science, spreadsheets or code.",
    example: { x: "0.00042", dir: "toSci" },
  },
  "mx-quadratic-solver": {
    what: "Solves an equation of the form ax^2 + bx + c = 0 for x. Give it a, b and c and it returns the answers, including complex ones when there are no real answers.",
    when: "You are checking algebra homework or solving a physics or geometry problem that leads to a quadratic.",
    example: { a: "1", b: "-3", c: "2" },
  },
  "mx-discriminant": {
    what: "Works out b^2 - 4ac for a quadratic equation, which tells you whether it has two, one or no real solutions.",
    when: "You want to know what kind of answers a quadratic has before solving it.",
    example: { a: "2", b: "4", c: "5" },
  },
  "mx-factorial": {
    what: "Calculates n factorial (n!), which is n multiplied by every whole number below it down to 1. Works exactly even for very large results.",
    when: "You are counting ways to arrange things or solving probability problems.",
    example: { n: "20" },
  },
  "mx-permutations": {
    what: "Counts how many ways you can pick r items from n items when the order matters (nPr).",
    when: "You want to know how many different podium finishes or ordered codes are possible.",
    example: { n: "10", r: "3" },
  },
  "mx-combinations": {
    what: "Counts how many ways you can pick r items from n items when order does not matter (nCr).",
    when: "You want to know how many different lottery tickets, teams or hands of cards are possible.",
    example: { n: "49", r: "6" },
  },
  "mx-fibonacci": {
    what: "Gives the nth Fibonacci number (each number is the sum of the two before it: 0, 1, 1, 2, 3, 5...) and lists the sequence up to it.",
    when: "You are studying sequences or need Fibonacci values for a coding exercise.",
    example: { n: "15" },
  },
  "mx-sum-1-to-n": {
    what: "Adds up every whole number from 1 to n, for example 1 to 100 gives 5050.",
    when: "You need a quick total of a running series, such as a triangle number, for maths or coding.",
    example: { n: "100" },
  },
  "mx-sum-list": {
    what: "Adds up a list of numbers you paste in, separated by commas, spaces or new lines.",
    when: "You have a column of numbers from a receipt or report and want the total fast.",
    example: { nums: "12.5, 7, 30, 4.25" },
  },
  "mx-product-list": {
    what: "Multiplies together all the numbers in a list you paste in, separated by commas, spaces or new lines.",
    when: "You need the product of several factors, such as growth rates or dimensions.",
    example: { nums: "2, 3, 4.5, 10" },
  },
  "mx-mean": {
    what: "Finds the average (mean) of a list of numbers: their total divided by how many there are.",
    when: "You want the average of test scores, prices or measurements.",
    example: { nums: "72, 85, 90, 64, 88" },
  },
  "mx-median": {
    what: "Finds the middle value of a list of numbers after sorting them. With an even count it takes the average of the two middle values.",
    when: "You want a typical value that is not pulled off by a few very large or small numbers, such as house prices.",
    example: { nums: "3, 9, 1, 7, 5, 20" },
  },
  "mx-mode": {
    what: "Finds the number or numbers that appear most often in a list, and how many times they appear.",
    when: "You want the most common value in survey answers, sizes or scores.",
    example: { nums: "1, 2, 2, 3, 3, 3, 4" },
  },
  "mx-range": {
    what: "Finds the difference between the biggest and smallest numbers in a list.",
    when: "You want a quick sense of how spread out a set of values is.",
    example: { nums: "14, 3, 27, 9, 18" },
  },
  "mx-variance": {
    what: "Measures how spread out a list of numbers is around their average. Choose sample (for data that is part of a bigger group) or population (for the whole group).",
    when: "You are doing statistics homework or analysing measurement data.",
    example: { nums: "2, 4, 4, 4, 5, 5, 7, 9", mode: "pop" },
  },
  "mx-std-dev": {
    what: "Calculates the standard deviation, a measure of how far numbers typically are from their average. Choose sample or population.",
    when: "You want to know how consistent a set of results is, such as test scores or response times.",
    example: { nums: "2, 4, 4, 4, 5, 5, 7, 9", mode: "sample" },
  },
  "mx-min-max": {
    what: "Finds the smallest and the largest number in a list you paste in.",
    when: "You want the lowest and highest value in a set of prices, temperatures or scores.",
    example: { nums: "18, -4, 7.5, 42, 0" },
  },
  "mx-abs": {
    what: "Gives the absolute value of a number, which is its size without the minus sign (-7 becomes 7).",
    when: "You care only about how big a difference is, not its direction.",
    example: { x: "-7.25" },
  },
  "mx-sign": {
    what: "Tells you whether a number is negative, zero or positive by returning -1, 0 or 1.",
    when: "You are checking the direction of a change or testing a formula that uses the sign function.",
    example: { x: "-42" },
  },
  "mx-round-decimals": {
    what: "Rounds a number to the number of decimal places you choose.",
    when: "You need a tidy value for money, measurements or a report.",
    example: { x: "3.14159", d: "2" },
  },
  "mx-floor-ceil-trunc": {
    what: "Rounds a number down (floor), up (ceil), or by simply cutting off the decimals (truncate).",
    when: "You need a specific rounding rule, for example how many full boxes you can fill or how many you must buy.",
    example: { x: "-3.7", op: "floor" },
  },
  "mx-clamp": {
    what: "Keeps a value inside a minimum and maximum: if it is too low you get the minimum, too high you get the maximum, otherwise the value itself.",
    when: "You are checking how a value will be limited, for example a volume between 0 and 100.",
    example: { x: "135", lo: "0", hi: "100" },
  },
  "mx-map-range": {
    what: "Converts a value from one scale to another in proportion, for example 0.25 on a 0 to 1 scale becomes 25 on a 0 to 100 scale.",
    when: "You are converting sensor readings, slider positions or scores between different ranges.",
    example: { x: "512", inLo: "0", inHi: "1023", outLo: "0", outHi: "100" },
  },
  "mx-lerp": {
    what: "Finds the value part of the way between a and b. t is how far along, where 0 gives a, 1 gives b and 0.5 gives the halfway point.",
    when: "You are animating, blending colors or estimating a value between two known points.",
    example: { a: "10", b: "50", t: "0.25" },
  },
  "mx-deg-rad": {
    what: "Converts an angle from degrees to radians, or from radians to degrees.",
    when: "Your code or calculator expects radians but you have degrees, or the other way round.",
    example: { x: "90", dir: "d2r" },
  },
  "mx-nth-root": {
    what: "Finds the nth root of a number, such as the square root (n = 2) or cube root (n = 3).",
    when: "You need a root for geometry, growth rates or other formulas.",
    example: { x: "27", n: "3" },
  },
  "mx-log-base": {
    what: "Calculates the logarithm of x in any base, which answers \"what power do I raise the base to, to get x?\".",
    when: "You need log base 2 for computer science, base 10 for science, or another base for a formula.",
    example: { x: "1024", b: "2" },
  },
  "mx-hypotenuse": {
    what: "Finds the long side of a right-angled triangle from the two shorter sides, using Pythagoras.",
    when: "You need a diagonal length, such as a screen size or a ramp length.",
    example: { a: "3", b: "4" },
  },
  "mx-distance-2d": {
    what: "Finds the straight-line distance between two points on a flat grid, given their x and y coordinates.",
    when: "You are solving geometry problems or measuring distances in a game or map grid.",
    example: { x1: "1", y1: "2", x2: "4", y2: "6" },
  },
  "mx-midpoint": {
    what: "Finds the point exactly halfway between two points on a flat grid.",
    when: "You need the center between two positions for geometry or layout work.",
    example: { x1: "2", y1: "3", x2: "8", y2: "11" },
  },
  "mx-slope": {
    what: "Finds the slope (steepness) of the line through two points: how much y changes for each step in x.",
    when: "You are working with straight-line graphs or rates of change. A vertical line has no slope.",
    example: { x1: "1", y1: "2", x2: "5", y2: "10" },
  },
  "mx-area": {
    what: "Calculates the area of a circle (from its radius), a rectangle (width and height) or a triangle (base and height).",
    when: "You are measuring floor space, material or a garden bed.",
    example: { shape: "rect", a: "4.5", b: "3" },
  },
  "mx-circumference": {
    what: "Calculates the distance around a circle from its radius.",
    when: "You need the edge length of a round table, wheel or garden bed.",
    example: { r: "10" },
  },
  "mx-is-power-of-two": {
    what: "Tells you whether a positive whole number is a power of two, such as 1, 2, 4, 8, 16 and so on.",
    when: "You are checking buffer sizes, texture sizes or other values that must be a power of two.",
    example: { n: "1024" },
  },
  "mx-next-power-of-two": {
    what: "Finds the smallest power of two (1, 2, 4, 8, 16...) that is equal to or bigger than your number.",
    when: "You need to round a size up to a power of two, for example for a texture or memory buffer.",
    example: { n: "1000" },
  },
};
