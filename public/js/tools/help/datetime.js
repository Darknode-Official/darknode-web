// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the datetime.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "dt-unix-to-human": {
    what: "Turns a Unix timestamp in seconds (the count of seconds since 1 January 1970, used by computers to store time) into readable dates in UTC, ISO format and your local time.",
    when: "You see a number like 1700000000 in a log or database and want to know what date and time it means.",
    example: { x: "1700000000" },
  },
  "dt-human-to-unix": {
    what: "Reads a date and time you type, like 2026-09-25 14:30, and gives back its Unix timestamp in seconds and in milliseconds.",
    when: "You need to put a specific date into code, an API call or a database query that expects a Unix timestamp. Dates without a zone are read as your local time.",
    example: { x: "2026-09-25 14:30" },
  },
  "dt-unix-millis-to-date": {
    what: "Turns a Unix timestamp in milliseconds (13 digits, as used by JavaScript and many APIs) into readable UTC, ISO and local dates.",
    when: "You have a long 13-digit time value from a web app or log and want to see the actual date.",
    example: { x: "1700000000000" },
  },
  "dt-date-to-unix-millis": {
    what: "Reads a date and time you type and gives back the Unix timestamp in milliseconds (milliseconds since 1 January 1970).",
    when: "You need a millisecond timestamp for JavaScript code, a test or an API. Dates without a zone are read as your local time.",
    example: { x: "2026-09-25 14:30" },
  },
  "dt-now": {
    what: "Shows the current time as a Unix timestamp (time counted from 1 January 1970) in seconds, milliseconds or microseconds.",
    when: "You need the current timestamp to paste into code, a test or a database query.",
    example: { unit: "ms" },
  },
  "dt-iso-parse": {
    what: "Reads an ISO-8601 date (the standard format like 2026-09-25T14:30:00Z) and lists its parts: year, month, day, hour, minute, second, milliseconds and weekday, in UTC.",
    when: "You want to check exactly what moment an ISO timestamp from an API or log refers to.",
    example: { x: "2026-09-25T14:30:00+02:00" },
  },
  "dt-format-pattern": {
    what: "Writes a date in the layout you describe with codes such as YYYY (year), MM (month), DD (day), HH (hour), mm (minutes) and dddd (weekday name).",
    when: "You need a date in a specific format for a report, file name or form. Blank pattern means YYYY-MM-DD HH:mm:ss.",
    example: { x: "2026-09-25 14:30", p: "dddd, MMMM D YYYY at h:mm A" },
  },
  "dt-tz-offset-convert": {
    what: "Takes a date and time in UTC (universal time) and a timezone offset like +05:30, and shows what the local clock time would be there.",
    when: "You have a UTC time from a server log and want to know the local time in a place with a known offset. It does not handle daylight saving automatically.",
    example: { x: "2026-09-25 14:30", off: "+05:30" },
  },
  "dt-tz-offset-list": {
    what: "Shows a fixed reference list of common UTC offsets (how many hours a place is ahead of or behind universal time) with example cities.",
    when: "You need to look up roughly what offset a city uses. Values are standard time and ignore daylight saving.",
    example: {},
  },
  "dt-duration-humanize": {
    what: "Turns a number of seconds into an easy-to-read length of time like 1d 2h 3m 4s.",
    when: "You have a duration in seconds (for example an uptime or a timeout) and want to understand how long it really is.",
    example: { x: "93784" },
  },
  "dt-duration-parse": {
    what: "Reads a short duration like 1h30m or 2d 4h (w = weeks, d = days, h = hours, m = minutes, s = seconds) and gives the total in seconds and minutes.",
    when: "A config or API wants a timeout in seconds and you think in hours and minutes.",
    example: { x: "1h30m" },
  },
  "dt-between-dates": {
    what: "Works out how much time lies between two dates and shows it in milliseconds, seconds, minutes, hours, days and a readable form.",
    when: "You want the exact gap between two events, for example a start and end time from a log.",
    example: { a: "2026-01-01", b: "2026-09-25 12:00" },
  },
  "dt-add-duration": {
    what: "Adds a length of time like 1h30m or 2d to a date and shows the resulting date and time.",
    when: "You need to know when something ends or expires, for example 90 days after a start date.",
    example: { x: "2026-09-25 14:30", dur: "2d 3h" },
  },
  "dt-subtract-duration": {
    what: "Subtracts a length of time like 1h30m or 2d from a date and shows the resulting date and time.",
    when: "You need to work backwards, for example to find when a job must start to finish by a deadline.",
    example: { x: "2026-09-25 14:30", dur: "1w 2d" },
  },
  "dt-day-of-week": {
    what: "Tells you which day of the week a date falls on, plus its number in two common numbering systems (Monday = 1 and Sunday = 0).",
    when: "You want to know what weekday a past or future date is, for example a birthday or a deadline.",
    example: { x: "2026-12-25" },
  },
  "dt-day-of-year": {
    what: "Tells you which day of the year a date is, counting 1 January as day 1 (up to 366 in leap years).",
    when: "You need the day-of-year number for a report, a log format or a planning sheet.",
    example: { x: "2026-09-25" },
  },
  "dt-iso-week": {
    what: "Gives the ISO week number for a date. ISO weeks start on Monday, and week 1 is the week containing the year's first Thursday.",
    when: "Your company or calendar plans by week number and you want to know which week a date is in. Early January or late December can belong to the neighbouring year.",
    example: { x: "2026-09-25" },
  },
  "dt-week-of-month": {
    what: "Tells you which week of its month a date falls in, counting weeks that start on Sunday.",
    when: "You schedule things like \"the 2nd week of the month\" and want to check which week a date belongs to.",
    example: { x: "2026-09-25" },
  },
  "dt-days-in-month": {
    what: "Tells you how many days the month of a given date has (28, 29, 30 or 31).",
    when: "You are planning billing, rent or schedules and need to know how long a particular month is.",
    example: { x: "2028-02-10" },
  },
  "dt-is-leap-year": {
    what: "Tells you whether a year is a leap year (a year with 366 days because February has 29 days).",
    when: "You are working with dates around February 29 and need to know if that day exists in a given year.",
    example: { x: "2028" },
  },
  "dt-age": {
    what: "Works out how old someone is today in years, months and days from their birthdate, plus the total number of days.",
    when: "You need an exact age, for example for a form or to check an eligibility cutoff.",
    example: { x: "1990-05-15" },
  },
  "dt-countdown": {
    what: "Shows how much time is left from now until a future date and time. If the date has passed, it says how long ago it was.",
    when: "You want to know how long remains until a launch, holiday or deadline.",
    example: { x: "2030-01-01 00:00" },
  },
  "dt-cron-describe": {
    what: "Explains a cron expression (a five-part schedule code used by servers, like */15 9-17 * * 1-5) by listing which minutes, hours, days, months and weekdays it runs on.",
    when: "You found a scheduled job and want to understand when it actually runs. Only numbers are supported, not names like MON or shortcuts like @daily.",
    example: { x: "*/15 9-17 * * 1-5" },
  },
  "dt-cron-next": {
    what: "Takes a cron expression (a five-part schedule code used by servers) and lists the next times it will run, starting from now, in your local time.",
    when: "You are setting up a scheduled job and want to confirm it will run when you expect. Only numeric fields are supported.",
    example: { x: "0 9 * * 1-5", n: "5" },
  },
  "dt-business-days": {
    what: "Counts the working days (Monday to Friday) between two dates, including both the start and end date.",
    when: "You need to know how many working days a project or notice period covers. Public holidays are not taken into account.",
    example: { a: "2026-09-01", b: "2026-09-30" },
  },
  "dt-quarter": {
    what: "Tells you which quarter of the year a date falls in: Q1 (Jan-Mar), Q2 (Apr-Jun), Q3 (Jul-Sep) or Q4 (Oct-Dec).",
    when: "You are sorting sales, invoices or reports by quarter. It uses calendar quarters, not a custom fiscal year.",
    example: { x: "2026-09-25" },
  },
  "dt-relative-time": {
    what: "Describes a date or Unix timestamp in everyday words relative to now, like \"3 days ago\" or \"in 2 months\".",
    when: "You want a quick sense of how long ago a log entry or event happened. Months are counted as 30 days, so it is approximate.",
    example: { x: "2020-01-01 12:00" },
  },
  "dt-weekday-name": {
    what: "Turns a weekday number into its name, where 0 is Sunday and 6 is Saturday.",
    when: "Code or a database stores weekdays as numbers and you want to know which day a number means.",
    example: { x: "3" },
  },
  "dt-month-name": {
    what: "Turns a month number from 1 to 12 into its name, where 1 is January.",
    when: "You see a month stored as a number and want the name for a report or label.",
    example: { x: "9" },
  },
  "dt-seconds-to-hms": {
    what: "Turns a number of seconds into a clock-style time HH:MM:SS (hours, minutes, seconds).",
    when: "You have a video length, call length or timer value in seconds and want it in the usual clock format.",
    example: { x: "3725" },
  },
  "dt-hms-to-seconds": {
    what: "Turns a clock-style time like 01:02:05 (HH:MM:SS) or 02:05 (MM:SS) into the total number of seconds.",
    when: "A tool or setting needs seconds, for example a video start time, but you have the time as hours and minutes.",
    example: { x: "01:02:05" },
  },
  "dt-12h-to-24h": {
    what: "Converts a time with AM or PM, like 02:30 PM, into 24-hour time, like 14:30.",
    when: "You need a time in 24-hour format for a form, a config or a timetable.",
    example: { x: "02:30 PM" },
  },
  "dt-24h-to-12h": {
    what: "Converts a 24-hour time, like 14:30, into 12-hour time with AM or PM, like 2:30 PM.",
    when: "You have a time in 24-hour format and want it in the style most people in the US read.",
    example: { x: "14:30" },
  },
  "dt-epoch-units": {
    what: "Shows a date, or a Unix timestamp (time counted from 1 January 1970), as a timestamp in seconds, milliseconds, microseconds and nanoseconds all at once.",
    when: "Different systems want timestamps in different units and you want all of them side by side.",
    example: { x: "2026-09-25 14:30" },
  },
  "dt-julian-day": {
    what: "Gives the Julian Day Number for a date: a simple day count used in astronomy and some science software, plus the exact Julian Date including the time of day.",
    when: "You are working with astronomy data or software that uses Julian days. The time you type is treated as UTC.",
    example: { x: "2026-09-25 12:00" },
  },
  "dt-from-julian": {
    what: "Turns a Julian Day Number (a day count used in astronomy) back into a normal calendar date.",
    when: "Your data or software gives dates as Julian day numbers and you want to see the actual date.",
    example: { x: "2461309" },
  },
  "dt-days-until-weekday": {
    what: "Tells you how many days from today until the next given weekday, where 0 is Sunday and 6 is Saturday.",
    when: "You want to know how many days until next Friday, for example. If today is that weekday, it counts to next week's.",
    example: { x: "5" },
  },
  "dt-days-until-date": {
    what: "Counts the whole days from today until a date you enter. If the date has passed, it says how many days ago it was.",
    when: "You want a simple day count to a trip, deadline or event.",
    example: { x: "2030-01-01" },
  },
  "dt-add-business-days": {
    what: "Moves forward (or backward, with a negative number) by a number of working days from a start date, skipping Saturdays and Sundays, and shows the resulting date.",
    when: "You need a due date like \"10 working days from today\". Public holidays are not skipped.",
    example: { x: "2026-09-25", n: "10" },
  },
  "dt-rfc2822": {
    what: "Writes a date or Unix timestamp in RFC 2822 format, the date style used in email headers, like Fri, 25 Sep 2026 14:30:00 +0000, always in UTC.",
    when: "You are building an email, RSS feed or HTTP header that needs this exact date style.",
    example: { x: "1700000000" },
  },
  "dt-to-iso8601": {
    what: "Writes a date or Unix timestamp in ISO 8601 format, the standard computer date style like 2026-09-25T14:30:00.000Z, in UTC.",
    when: "An API, JSON file or database wants dates in ISO format and you have a timestamp or a plain date.",
    example: { x: "1700000000" },
  },
  "dt-week-bounds": {
    what: "Shows the first and last day of the week that contains your date. You choose whether weeks start on Monday or Sunday.",
    when: "You are building a weekly report and need the exact start and end dates for that week.",
    example: { x: "2026-09-25", start: "monday" },
  },
  "dt-month-bounds": {
    what: "Shows the very first moment (00:00:00 on the 1st) and the very last moment (23:59:59 on the last day) of the month containing your date.",
    when: "You need a date range for a monthly report or database query.",
    example: { x: "2026-02-14" },
  },
  "dt-day-bounds": {
    what: "Shows the very start (00:00:00) and very end (23:59:59.999) of the day containing your date, in your local time.",
    when: "You need the full time range of one day, for example to filter logs or records from that date.",
    example: { x: "2026-09-25 14:30" },
  },
  "dt-minutes-since-midnight": {
    what: "Tells you how many minutes have passed since midnight at a given time, for example 14:30 is 870 minutes.",
    when: "A system stores times of day as minutes after midnight, such as opening hours or schedules, and you need that number.",
    example: { x: "14:30" },
  },
  "dt-decimal-hours": {
    what: "Converts between decimal hours (like 2.5) and clock time (like 02:30), in whichever direction you choose.",
    when: "You fill in timesheets or invoices that use decimal hours but you tracked time as hours and minutes, or the reverse.",
    example: { x: "7.75", mode: "to-hms" },
  },
  "dt-diff-humanized": {
    what: "Shows the time between two dates in a readable form like 1d 2h 30m and says which of the two is later.",
    when: "You want a quick, human-friendly answer to \"how long between these two times\".",
    example: { a: "2026-01-01 08:00", b: "2026-01-02 10:30" },
  },
  "dt-is-weekend": {
    what: "Tells you whether a date falls on a Saturday or Sunday, and names the weekday.",
    when: "You are planning an event or delivery and want to check if a date is a weekend day.",
    example: { x: "2026-09-26" },
  },
  "dt-next-weekday": {
    what: "Gives the date of the next chosen weekday (0 is Sunday, 6 is Saturday), counting from today or from a start date you give.",
    when: "You want the date of \"next Monday\" from a particular day, for example to schedule a meeting.",
    example: { x: "1", from: "2026-09-25" },
  },
  "dt-ordinal-date": {
    what: "Writes the day of the month with its ending, like 1st, 2nd, 3rd or 25th. Enter a full date or just a day number.",
    when: "You are writing a letter, invitation or label and want a date like \"25th of September 2026\".",
    example: { x: "2026-09-22" },
  },
  "dt-season": {
    what: "Tells you which season a date is in, using approximate fixed dates for the astronomical seasons in the Northern Hemisphere.",
    when: "You want to label dates by season, for example for a travel or garden plan. The Southern Hemisphere is not handled.",
    example: { x: "2026-07-15" },
  },
  "dt-moon-phase": {
    what: "Estimates the phase of the moon (for example Full Moon or Waxing Crescent) on a date, its age in days and roughly how much of it is lit.",
    when: "You want a quick idea of the moon on a date, for example for night photography. It is an approximation, not an exact astronomical figure.",
    example: { x: "2026-09-25" },
  },
  "dt-tz-abbrev-table": {
    what: "Shows a fixed reference table of common timezone abbreviations (like EST, PST, CET, IST) and their offsets from UTC (universal time).",
    when: "You see a time written as \"3 PM EST\" and need to know how far that zone is from UTC.",
    example: {},
  },
  "dt-now-hex": {
    what: "Shows the current Unix time (time counted from 1 January 1970) in seconds and milliseconds, in normal numbers and in hexadecimal (base 16).",
    when: "You are debugging low-level code, IDs or file formats that store the time in hexadecimal.",
    example: {},
  },
  "dt-seconds-breakdown": {
    what: "Breaks a number of seconds into weeks, days, hours, minutes and seconds.",
    when: "You have a large number of seconds, such as an uptime counter, and want to see how long it really is.",
    example: { x: "1000000" },
  },
  "dt-millis-humanize": {
    what: "Turns a number of milliseconds into a readable length of time like 1d 2h 3m 4s, including any leftover milliseconds.",
    when: "Your logs or measurements show durations in milliseconds and you want to read them easily.",
    example: { x: "93784250" },
  },
  "dt-nanos-to-seconds": {
    what: "Converts nanoseconds (billionths of a second) into seconds, milliseconds and microseconds.",
    when: "A program or benchmark reports times in nanoseconds and you want a more familiar unit.",
    example: { x: "1500000000" },
  },
  "dt-stopwatch-splits": {
    what: "Takes a list of lap times in seconds and shows the running total after each lap, plus the overall total, average, fastest and slowest lap.",
    when: "You timed laps for running, swimming or a game and want the totals worked out.",
    example: { text: "62.4\n59.8\n61.1\n58.7" },
  },
  "dt-meeting-times": {
    what: "Takes a time in one timezone offset and shows what time it is in UTC and in each of the other offsets you list, with the weekday.",
    when: "You are setting up a meeting across countries and want each person's local time. You enter offsets like -05:00, not city names, so check daylight saving yourself.",
    example: { x: "2026-09-25 09:00", from: "-05:00", to: "+00:00, +05:30, +09:00" },
  },
  "dt-days-since": {
    what: "Counts the whole days that have passed since a past date up to today.",
    when: "You want to know how many days since an event, like a start date, last incident or anniversary.",
    example: { x: "2020-01-01" },
  },
  "dt-date-validator": {
    what: "Checks whether a date written as YYYY-MM-DD really exists on the calendar, and if not, explains why.",
    when: "You are checking form input or data and want to catch impossible dates like 2026-02-30 or 2026-13-01.",
    example: { x: "2028-02-29" },
  },
  "dt-days-in-year": {
    what: "Tells you whether a year has 365 or 366 days.",
    when: "You are doing yearly calculations, such as daily interest or averages, and need the exact number of days.",
    example: { x: "2028" },
  },
  "dt-weeks-in-year": {
    what: "Tells you whether a year has 52 or 53 ISO weeks (the Monday-start week numbering used in business and Europe).",
    when: "You plan by week number and need to know if a year has a week 53.",
    example: { x: "2026" },
  },
  "dt-percent-of-day": {
    what: "Tells you what percentage of the day has passed at a given time, for example 12:00 is 50%.",
    when: "You want a quick feel for how much of the day is gone, for example for a progress bar.",
    example: { x: "14:30" },
  },
  "dt-percent-of-year": {
    what: "Tells you what percentage of the year has passed on a given date.",
    when: "You are tracking yearly goals or budgets and want to see how far through the year a date is.",
    example: { x: "2026-09-25" },
  },
  "dt-next-leap-year": {
    what: "Finds the first leap year (a year with 366 days) on or after the year you enter.",
    when: "You want to know when February 29 will next happen, for example for a leap-day birthday.",
    example: { x: "2026" },
  },
  "dt-time-until-midnight": {
    what: "Shows how much time is left until the next midnight from a time you give, or from now if you leave it blank.",
    when: "You want to know how long remains in the day, for example before a daily limit or deal resets.",
    example: { x: "14:30" },
  },
  "dt-week-to-dates": {
    what: "Takes a year and an ISO week number (Monday-start week numbering) and shows the Monday and Sunday dates of that week.",
    when: "Someone mentions \"week 39\" and you need to know which actual dates that covers.",
    example: { y: "2026", w: "39" },
  },
};
