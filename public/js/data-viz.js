// data-viz.js
// Lightweight, dependency-free data visualization library.
// Provides statistical helpers, color utilities, and SVG/HTML chart
// renderers used across the darknode dashboards.
//
// Design rules followed throughout this file:
// - Categorical hues are used in a fixed order and never cycled.
// - Sequential palettes interpolate a single hue range light -> dark.
// - No dual-axis charts are ever produced.
// - Marks are thin: 2px lines, 4px rounded bar ends, 2px gaps between fills.
// - Any chart with 2+ series always renders a legend.
// - Text stays in neutral ink; color is reserved for data identity.
// - Grid lines and axes are recessive (light gray).

const SVG_NS = 'http://www.w3.org/2000/svg';

// Fixed-order categorical palette. Never cycle or reorder these -- a slot
// always maps to the same semantic position across charts.
const DEFAULT_PALETTE = [
  '#2563eb', '#d97706', '#059669', '#dc2626',
  '#7c3aed', '#0891b2', '#c026d3', '#65a30d'
];

const INK_PRIMARY = '#111827';
const INK_SECONDARY = '#374151';
const INK_MUTED = '#6b7280';
const GRID_COLOR = '#e5e7eb';
const AXIS_COLOR = '#9ca3af';

let uidCounter = 0;
const nextUid = (prefix) => `${prefix}-${Date.now().toString(36)}-${(uidCounter++).toString(36)}`;

// ─────────────────────────────────────────────────────────────────────────
// Statistical helpers
// ─────────────────────────────────────────────────────────────────────────

export function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  let sum = 0;
  for (let i = 0; i < arr.length; i++) sum += arr[i];
  return sum / arr.length;
}

export function median(arr) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

export function stddev(arr) {
  if (!arr || arr.length === 0) return 0;
  const m = mean(arr);
  const variance = mean(arr.map((v) => (v - m) ** 2));
  return Math.sqrt(variance);
}

export function percentile(arr, p) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  if (sorted.length === 1) return sorted[0];
  const clampedP = Math.min(1, Math.max(0, p));
  const rank = clampedP * (sorted.length - 1);
  const lowerIndex = Math.floor(rank);
  const upperIndex = Math.ceil(rank);
  if (lowerIndex === upperIndex) return sorted[lowerIndex];
  const frac = rank - lowerIndex;
  return sorted[lowerIndex] + (sorted[upperIndex] - sorted[lowerIndex]) * frac;
}

export function histogram(arr, bins) {
  if (!arr || arr.length === 0 || !bins || bins < 1) return [];
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  const range = max - min;
  const width = range === 0 ? 1 : range / bins;
  const result = [];
  for (let i = 0; i < bins; i++) {
    const binStart = min + i * width;
    const binEnd = i === bins - 1 ? max : min + (i + 1) * width;
    result.push({ binStart, binEnd, count: 0 });
  }
  for (const value of arr) {
    if (range === 0) {
      result[0].count++;
      continue;
    }
    let idx = Math.floor((value - min) / width);
    if (idx >= bins) idx = bins - 1;
    if (idx < 0) idx = 0;
    result[idx].count++;
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────
// Color helpers
// ─────────────────────────────────────────────────────────────────────────

function hexToRgb(hex) {
  const clean = hex.replace('#', '');
  const full = clean.length === 3
    ? clean.split('').map((c) => c + c).join('')
    : clean;
  const num = parseInt(full, 16);
  return {
    r: (num >> 16) & 255,
    g: (num >> 8) & 255,
    b: num & 255
  };
}

function rgbToHex(r, g, b) {
  const toHex = (v) => {
    const clamped = Math.max(0, Math.min(255, Math.round(v)));
    return clamped.toString(16).padStart(2, '0');
  };
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function interpolateRgb(colorA, colorB, t) {
  const a = hexToRgb(colorA);
  const b = hexToRgb(colorB);
  return rgbToHex(
    lerp(a.r, b.r, t),
    lerp(a.g, b.g, t),
    lerp(a.b, b.b, t)
  );
}

// Relative luminance (WCAG-style approximation) used to decide whether
// text on top of a fill should be white or black.
function relativeLuminance(hex) {
  const { r, g, b } = hexToRgb(hex);
  const channel = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/**
 * Generate `steps` hex colors interpolated across one or more palette stops.
 * Interpolation happens in RGB space. Intended for sequential (single hue,
 * light -> dark) magnitude encodings -- never use this to fabricate a
 * categorical palette.
 */
export function colorScale(min, max, steps, palette) {
  const stops = palette && palette.length >= 2 ? palette : ['#eff6ff', '#2563eb'];
  const count = Math.max(1, Math.floor(steps));
  const colors = [];
  for (let i = 0; i < count; i++) {
    const t = count === 1 ? 0 : i / (count - 1);
    const segment = t * (stops.length - 1);
    const segIndex = Math.min(stops.length - 2, Math.floor(segment));
    const segT = segment - segIndex;
    colors.push(interpolateRgb(stops[segIndex], stops[segIndex + 1], segT));
  }
  return colors;
}

function valueToScaleColor(value, min, max, stops) {
  const range = max - min;
  const t = range === 0 ? 0 : (value - min) / range;
  const clampedT = Math.min(1, Math.max(0, t));
  const segment = clampedT * (stops.length - 1);
  const segIndex = Math.min(stops.length - 2, Math.floor(segment));
  const segT = segment - segIndex;
  return interpolateRgb(stops[segIndex], stops[segIndex + 1], segT);
}

// ─────────────────────────────────────────────────────────────────────────
// Small SVG builder utilities
// ─────────────────────────────────────────────────────────────────────────

function createSvg(width, height) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('xmlns', SVG_NS);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.style.display = 'block';
  svg.style.maxWidth = '100%';
  return svg;
}

function el(tag, attrs = {}, ns = SVG_NS) {
  const node = document.createElementNS(ns, tag);
  for (const key in attrs) {
    if (attrs[key] !== undefined && attrs[key] !== null) {
      node.setAttribute(key, String(attrs[key]));
    }
  }
  return node;
}

function textEl(x, y, content, attrs = {}) {
  const t = el('text', { x, y, ...attrs });
  t.textContent = content;
  return t;
}

function clearContainer(container) {
  container.innerHTML = '';
}

// ─────────────────────────────────────────────────────────────────────────
// Bar chart
// ─────────────────────────────────────────────────────────────────────────

export function barChart(container, data, options = {}) {
  const opts = {
    width: 500,
    barHeight: 28,
    gap: 6,
    showValues: true,
    animate: true,
    title: '',
    ...options
  };

  const titleHeight = opts.title ? 32 : 0;
  const paddingTop = titleHeight + 8;
  const paddingBottom = 24;
  const rowHeight = opts.barHeight + opts.gap;
  const chartHeight = data.length * rowHeight;
  const height = opts.height || paddingTop + chartHeight + paddingBottom;

  const width = opts.width;
  const labelWidth = Math.min(160, Math.max(70, width * 0.28));
  const valueGutter = opts.showValues ? 56 : 12;
  const plotLeft = labelWidth + 10;
  const plotRight = width - valueGutter;
  const plotWidth = Math.max(10, plotRight - plotLeft);

  const maxValue = Math.max(1, ...data.map((d) => d.value));

  clearContainer(container);
  const svg = createSvg(width, height);

  const uid = nextUid('bar');
  if (opts.animate) {
    const style = el('style', {}, SVG_NS);
    style.textContent = `.${uid}-rect { transition: width 0.6s ease; }`;
    svg.appendChild(style);
  }

  if (opts.title) {
    svg.appendChild(textEl(0, 20, opts.title, {
      fill: INK_PRIMARY,
      'font-size': '14px',
      'font-weight': '600',
      'font-family': 'inherit'
    }));
  }

  // Baseline axis
  const axisY0 = paddingTop;
  const axisY1 = paddingTop + chartHeight;
  svg.appendChild(el('line', {
    x1: plotLeft, y1: axisY0, x2: plotLeft, y2: axisY1,
    stroke: AXIS_COLOR, 'stroke-width': 1
  }));

  data.forEach((d, i) => {
    const rowY = paddingTop + i * rowHeight;
    const barY = rowY + (opts.gap / 2);
    const finalWidth = Math.max(0, (d.value / maxValue) * plotWidth);
    const color = d.color || DEFAULT_PALETTE[i % DEFAULT_PALETTE.length];

    // Label (neutral ink, never colored)
    svg.appendChild(textEl(plotLeft - 10, barY + opts.barHeight / 2 + 4, d.label, {
      fill: INK_SECONDARY,
      'font-size': '12px',
      'text-anchor': 'end',
      'font-family': 'inherit'
    }));

    const rect = el('rect', {
      x: plotLeft,
      y: barY,
      width: opts.animate ? 0 : finalWidth,
      height: opts.barHeight,
      rx: 4,
      ry: 4,
      fill: color,
      class: `${uid}-rect`
    });
    svg.appendChild(rect);

    if (opts.showValues) {
      const valueLabel = textEl(plotLeft + finalWidth + 8, barY + opts.barHeight / 2 + 4, formatNumber(d.value), {
        fill: INK_MUTED,
        'font-size': '12px',
        'font-family': 'inherit'
      });
      svg.appendChild(valueLabel);
    }

    if (opts.animate) {
      setTimeout(() => {
        rect.setAttribute('width', String(finalWidth));
      }, 20 + i * 25);
    }
  });

  container.appendChild(svg);
  return svg;
}

function formatNumber(n) {
  if (typeof n !== 'number') return String(n);
  if (Math.abs(n) >= 1000) return n.toLocaleString('en-US');
  if (Number.isInteger(n)) return String(n);
  return n.toFixed(1);
}

// ─────────────────────────────────────────────────────────────────────────
// Line chart
// ─────────────────────────────────────────────────────────────────────────

export function lineChart(container, data, options = {}) {
  const opts = {
    width: 500,
    height: 300,
    showDots: true,
    showArea: false,
    showGrid: true,
    xLabel: '',
    yLabel: '',
    title: '',
    colors: DEFAULT_PALETTE,
    ...options
  };

  // Normalize into a multi-series shape.
  const series = (data.length && data[0].points)
    ? data
    : [{ label: '', points: data, color: opts.colors[0] }];

  const allPoints = series.flatMap((s) => s.points);
  const xValues = allPoints.map((p) => p.x);
  const yValues = allPoints.map((p) => p.y);

  const xMin = Math.min(...xValues);
  const xMax = Math.max(...xValues);
  let yMin = Math.min(...yValues);
  let yMax = Math.max(...yValues);

  // 10% padding on y range.
  const yRange = yMax - yMin || Math.abs(yMax) || 1;
  const yPad = yRange * 0.1;
  yMin -= yPad;
  yMax += yPad;

  const width = opts.width;
  const height = opts.height;
  const titleHeight = opts.title ? 28 : 0;
  const legendNeeded = series.length >= 2;
  const legendHeight = legendNeeded ? 24 : 0;
  const xAxisLabelHeight = opts.xLabel ? 20 : 0;
  const yAxisLabelWidth = opts.yLabel ? 16 : 0;

  const marginTop = titleHeight + 10;
  const marginBottom = 28 + xAxisLabelHeight + legendHeight;
  const marginLeft = 48 + yAxisLabelWidth;
  const marginRight = 16;

  const plotWidth = Math.max(10, width - marginLeft - marginRight);
  const plotHeight = Math.max(10, height - marginTop - marginBottom);
  const plotX0 = marginLeft;
  const plotY0 = marginTop;
  const plotX1 = marginLeft + plotWidth;
  const plotY1 = marginTop + plotHeight;

  const xScale = (x) => {
    const range = xMax - xMin || 1;
    return plotX0 + ((x - xMin) / range) * plotWidth;
  };
  const yScale = (y) => {
    const range = yMax - yMin || 1;
    return plotY1 - ((y - yMin) / range) * plotHeight;
  };

  clearContainer(container);
  const svg = createSvg(width, height);

  if (opts.title) {
    svg.appendChild(textEl(0, 18, opts.title, {
      fill: INK_PRIMARY,
      'font-size': '14px',
      'font-weight': '600',
      'font-family': 'inherit'
    }));
  }

  // Grid: horizontal dashed lines at 4 evenly spaced steps.
  const gridSteps = 4;
  if (opts.showGrid) {
    for (let i = 0; i <= gridSteps; i++) {
      const gy = plotY0 + (i / gridSteps) * plotHeight;
      svg.appendChild(el('line', {
        x1: plotX0, y1: gy, x2: plotX1, y2: gy,
        stroke: GRID_COLOR, 'stroke-width': 1, 'stroke-dasharray': '3,3'
      }));
      const yVal = yMax - (i / gridSteps) * (yMax - yMin);
      svg.appendChild(textEl(plotX0 - 8, gy + 4, formatNumber(yVal), {
        fill: INK_MUTED, 'font-size': '11px', 'text-anchor': 'end', 'font-family': 'inherit'
      }));
    }
  }

  // Axes (recessive).
  svg.appendChild(el('line', {
    x1: plotX0, y1: plotY1, x2: plotX1, y2: plotY1,
    stroke: AXIS_COLOR, 'stroke-width': 1
  }));
  svg.appendChild(el('line', {
    x1: plotX0, y1: plotY0, x2: plotX0, y2: plotY1,
    stroke: AXIS_COLOR, 'stroke-width': 1
  }));

  // X tick labels: first, middle, last of the merged x domain.
  const xTickCount = Math.min(6, new Set(xValues).size || 1);
  if (xTickCount > 1) {
    for (let i = 0; i < xTickCount; i++) {
      const xv = xMin + (i / (xTickCount - 1)) * (xMax - xMin);
      const sx = xScale(xv);
      svg.appendChild(textEl(sx, plotY1 + 16, formatNumber(xv), {
        fill: INK_MUTED, 'font-size': '11px', 'text-anchor': 'middle', 'font-family': 'inherit'
      }));
    }
  } else if (allPoints.length) {
    svg.appendChild(textEl(xScale(xMin), plotY1 + 16, formatNumber(xMin), {
      fill: INK_MUTED, 'font-size': '11px', 'text-anchor': 'middle', 'font-family': 'inherit'
    }));
  }

  series.forEach((s, si) => {
    const color = s.color || opts.colors[si % opts.colors.length];
    const points = s.points.map((p) => ({ x: xScale(p.x), y: yScale(p.y) }));
    const pointStr = points.map((p) => `${p.x},${p.y}`).join(' ');

    if (opts.showArea) {
      const areaPoints = [
        `${points[0].x},${plotY1}`,
        pointStr,
        `${points[points.length - 1].x},${plotY1}`
      ].join(' ');
      svg.appendChild(el('polygon', {
        points: areaPoints,
        fill: color,
        opacity: 0.15,
        stroke: 'none'
      }));
    }

    svg.appendChild(el('polyline', {
      points: pointStr,
      fill: 'none',
      stroke: color,
      'stroke-width': 2,
      'stroke-linejoin': 'round',
      'stroke-linecap': 'round'
    }));

    if (opts.showDots) {
      points.forEach((p) => {
        svg.appendChild(el('circle', {
          cx: p.x, cy: p.y, r: 4,
          fill: color, stroke: '#ffffff', 'stroke-width': 2
        }));
      });
    }
  });

  // Axis labels.
  if (opts.yLabel) {
    const label = textEl(0, 0, opts.yLabel, {
      fill: INK_MUTED, 'font-size': '11px', 'text-anchor': 'middle', 'font-family': 'inherit'
    });
    label.setAttribute('transform', `translate(14, ${plotY0 + plotHeight / 2}) rotate(-90)`);
    svg.appendChild(label);
  }
  if (opts.xLabel) {
    svg.appendChild(textEl(plotX0 + plotWidth / 2, plotY1 + xAxisLabelHeight + 12, opts.xLabel, {
      fill: INK_MUTED, 'font-size': '11px', 'text-anchor': 'middle', 'font-family': 'inherit'
    }));
  }

  // Legend for 2+ series.
  if (legendNeeded) {
    const legendY = height - legendHeight / 2 - 4;
    let legendX = plotX0;
    series.forEach((s, si) => {
      const color = s.color || opts.colors[si % opts.colors.length];
      svg.appendChild(el('line', {
        x1: legendX, y1: legendY, x2: legendX + 16, y2: legendY,
        stroke: color, 'stroke-width': 2, 'stroke-linecap': 'round'
      }));
      const label = s.label || `Series ${si + 1}`;
      const labelEl = textEl(legendX + 22, legendY + 4, label, {
        fill: INK_SECONDARY, 'font-size': '11px', 'font-family': 'inherit'
      });
      svg.appendChild(labelEl);
      // Rough width estimate to lay out the next legend entry.
      legendX += 22 + label.length * 6.2 + 20;
    });
  }

  container.appendChild(svg);
  return svg;
}

// ─────────────────────────────────────────────────────────────────────────
// Pie / donut chart
// ─────────────────────────────────────────────────────────────────────────

export function pieChart(container, data, options = {}) {
  const opts = {
    width: 300,
    height: 300,
    donut: false,
    showLabels: true,
    showLegend: true,
    title: '',
    ...options
  };

  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  const titleHeight = opts.title ? 26 : 0;
  const legendHeight = opts.showLegend ? data.length * 20 + 10 : 0;
  const chartAreaHeight = opts.height - titleHeight - legendHeight;

  const cx = opts.width / 2;
  const cy = titleHeight + chartAreaHeight / 2;
  const outerRadius = Math.max(10, Math.min(opts.width, chartAreaHeight) / 2 - 12);
  const innerRadius = opts.donut ? outerRadius * 0.6 : 0;

  const totalHeight = opts.height;
  clearContainer(container);
  const svg = createSvg(opts.width, totalHeight);

  if (opts.title) {
    svg.appendChild(textEl(opts.width / 2, 18, opts.title, {
      fill: INK_PRIMARY,
      'font-size': '14px',
      'font-weight': '600',
      'text-anchor': 'middle',
      'font-family': 'inherit'
    }));
  }

  const polarToCartesian = (radius, angle) => ({
    x: cx + radius * Math.cos(angle),
    y: cy + radius * Math.sin(angle)
  });

  let currentAngle = -Math.PI / 2; // start at 12 o'clock

  data.forEach((d, i) => {
    const color = d.color || DEFAULT_PALETTE[i % DEFAULT_PALETTE.length];
    const fraction = d.value / total;
    const startAngle = currentAngle;
    const endAngle = currentAngle + fraction * 2 * Math.PI;
    const angleSpan = endAngle - startAngle;
    const largeArcFlag = angleSpan > Math.PI ? 1 : 0;

    const outerStart = polarToCartesian(outerRadius, startAngle);
    const outerEnd = polarToCartesian(outerRadius, endAngle);

    let pathData;
    if (opts.donut) {
      const innerStart = polarToCartesian(innerRadius, startAngle);
      const innerEnd = polarToCartesian(innerRadius, endAngle);
      pathData = [
        `M ${outerStart.x} ${outerStart.y}`,
        `A ${outerRadius} ${outerRadius} 0 ${largeArcFlag} 1 ${outerEnd.x} ${outerEnd.y}`,
        `L ${innerEnd.x} ${innerEnd.y}`,
        `A ${innerRadius} ${innerRadius} 0 ${largeArcFlag} 0 ${innerStart.x} ${innerStart.y}`,
        'Z'
      ].join(' ');
    } else {
      pathData = [
        `M ${cx} ${cy}`,
        `L ${outerStart.x} ${outerStart.y}`,
        `A ${outerRadius} ${outerRadius} 0 ${largeArcFlag} 1 ${outerEnd.x} ${outerEnd.y}`,
        'Z'
      ].join(' ');
    }

    const path = el('path', {
      d: pathData,
      fill: color,
      stroke: '#ffffff',
      'stroke-width': 2
    });
    svg.appendChild(path);

    if (opts.showLabels && fraction > 0.0001) {
      const midAngle = (startAngle + endAngle) / 2;
      const percentText = `${Math.round(fraction * 100)}%`;
      // Small slices (< 6%) get their label pushed outside the arc.
      const labelRadius = fraction < 0.06
        ? outerRadius + 14
        : (opts.donut ? (innerRadius + outerRadius) / 2 : outerRadius * 0.65);
      const labelPos = polarToCartesian(labelRadius, midAngle);
      const labelColor = fraction < 0.06 ? INK_MUTED : (relativeLuminance(color) < 0.5 ? '#ffffff' : '#111827');
      svg.appendChild(textEl(labelPos.x, labelPos.y + 4, percentText, {
        fill: labelColor,
        'font-size': '11px',
        'text-anchor': 'middle',
        'font-family': 'inherit'
      }));
    }

    currentAngle = endAngle;
  });

  if (opts.showLegend) {
    const legendTop = titleHeight + chartAreaHeight + 6;
    data.forEach((d, i) => {
      const color = d.color || DEFAULT_PALETTE[i % DEFAULT_PALETTE.length];
      const rowY = legendTop + i * 20;
      svg.appendChild(el('rect', {
        x: 4, y: rowY, width: 10, height: 10, rx: 2, ry: 2, fill: color
      }));
      svg.appendChild(textEl(20, rowY + 9, `${d.label} (${formatNumber(d.value)})`, {
        fill: INK_SECONDARY,
        'font-size': '11px',
        'font-family': 'inherit'
      }));
    });
  }

  container.appendChild(svg);
  return svg;
}

// ─────────────────────────────────────────────────────────────────────────
// Sparkline
// ─────────────────────────────────────────────────────────────────────────

export function sparkline(container, values, options = {}) {
  const opts = {
    width: 120,
    height: 32,
    color: '#2563eb',
    strokeWidth: 1.5,
    showMinMax: false,
    ...options
  };

  clearContainer(container);
  const svg = createSvg(opts.width, opts.height);

  if (!values || values.length === 0) {
    container.appendChild(svg);
    return svg;
  }

  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const padY = opts.strokeWidth * 2;
  const padX = 2;

  const points = values.map((v, i) => {
    const x = values.length === 1
      ? opts.width / 2
      : padX + (i / (values.length - 1)) * (opts.width - padX * 2);
    const y = opts.height - padY - ((v - min) / range) * (opts.height - padY * 2);
    return { x, y, v };
  });

  svg.appendChild(el('polyline', {
    points: points.map((p) => `${p.x},${p.y}`).join(' '),
    fill: 'none',
    stroke: opts.color,
    'stroke-width': opts.strokeWidth,
    'stroke-linejoin': 'round',
    'stroke-linecap': 'round'
  }));

  if (opts.showMinMax) {
    const minPoint = points.reduce((a, b) => (b.v < a.v ? b : a));
    const maxPoint = points.reduce((a, b) => (b.v > a.v ? b : a));
    svg.appendChild(el('circle', {
      cx: minPoint.x, cy: minPoint.y, r: 2.5, fill: '#dc2626'
    }));
    svg.appendChild(el('circle', {
      cx: maxPoint.x, cy: maxPoint.y, r: 2.5, fill: '#059669'
    }));
  }

  container.appendChild(svg);
  return svg;
}

// ─────────────────────────────────────────────────────────────────────────
// Heatmap (HTML table based)
// ─────────────────────────────────────────────────────────────────────────

export function heatmap(container, data, options = {}) {
  const opts = {
    rowLabels: [],
    colLabels: [],
    colorScale: ['#eff6ff', '#3b82f6', '#1e3a5f'],
    title: '',
    cellSize: 40,
    ...options
  };

  const flat = data.flat();
  const min = Math.min(...flat);
  const max = Math.max(...flat);

  const wrapper = document.createElement('div');
  wrapper.className = 'dv-heatmap';

  if (opts.title) {
    const titleEl = document.createElement('div');
    titleEl.textContent = opts.title;
    titleEl.style.cssText = `font-size:14px;font-weight:600;color:${INK_PRIMARY};margin-bottom:8px;font-family:inherit;`;
    wrapper.appendChild(titleEl);
  }

  const tableWrap = document.createElement('div');
  tableWrap.style.overflowX = 'auto';

  const table = document.createElement('table');
  table.style.cssText = 'border-collapse:collapse;font-family:inherit;';

  if (opts.colLabels.length) {
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    // Empty corner cell if row labels exist.
    if (opts.rowLabels.length) {
      const corner = document.createElement('th');
      corner.style.cssText = `width:${opts.cellSize}px;min-width:${opts.cellSize}px;`;
      headRow.appendChild(corner);
    }
    opts.colLabels.forEach((label) => {
      const th = document.createElement('th');
      th.textContent = label;
      th.style.cssText = `
        font-size:11px;font-weight:500;color:${INK_MUTED};
        padding:4px 6px;text-align:center;width:${opts.cellSize}px;
        min-width:${opts.cellSize}px;white-space:nowrap;
      `;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
  }

  const tbody = document.createElement('tbody');
  data.forEach((row, r) => {
    const tr = document.createElement('tr');
    if (opts.rowLabels.length) {
      const th = document.createElement('th');
      th.textContent = opts.rowLabels[r] || '';
      th.style.cssText = `
        font-size:11px;font-weight:500;color:${INK_MUTED};
        padding:4px 8px;text-align:right;white-space:nowrap;
      `;
      tr.appendChild(th);
    }
    row.forEach((value) => {
      const td = document.createElement('td');
      const bg = valueToScaleColor(value, min, max, opts.colorScale);
      const textColor = relativeLuminance(bg) < 0.5 ? '#ffffff' : '#111827';
      td.textContent = formatNumber(value);
      td.style.cssText = `
        background:${bg};color:${textColor};
        width:${opts.cellSize}px;height:${opts.cellSize}px;
        min-width:${opts.cellSize}px;
        text-align:center;font-size:11px;font-family:inherit;
        border:2px solid #ffffff;box-sizing:border-box;
      `;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  tableWrap.appendChild(table);
  wrapper.appendChild(tableWrap);

  clearContainer(container);
  container.appendChild(wrapper);
  return wrapper;
}

// ─────────────────────────────────────────────────────────────────────────
// Gauge
// ─────────────────────────────────────────────────────────────────────────

export function gauge(container, value, options = {}) {
  const opts = {
    min: 0,
    max: 100,
    width: 200,
    height: 120,
    zones: [
      { from: 0, to: 50, color: '#22c55e' },
      { from: 50, to: 80, color: '#f59e0b' },
      { from: 80, to: 100, color: '#ef4444' }
    ],
    label: '',
    showValue: true,
    ...options
  };

  const width = opts.width;
  const height = opts.height;
  const cx = width / 2;
  const cy = height - 24;
  const radius = Math.min(width / 2 - 10, height - 40);
  const trackWidth = Math.max(8, radius * 0.22);

  clearContainer(container);
  const svg = createSvg(width, height);

  // Semicircle spans from 180deg (left, PI) to 0deg (right), opening downward.
  // Angle 0 = pointing right (0,radius offset), PI = pointing left.
  // We map value range onto angle range [PI, 0] traveling over the top.
  const valueToAngle = (v) => {
    const clamped = Math.max(opts.min, Math.min(opts.max, v));
    const t = (clamped - opts.min) / (opts.max - opts.min || 1);
    return Math.PI - t * Math.PI; // PI at min, 0 at max
  };

  const pointOnArc = (angle, r) => ({
    x: cx + r * Math.cos(angle),
    y: cy - r * Math.sin(angle)
  });

  // Draw each zone as an arc segment along the semicircle track.
  opts.zones.forEach((zone) => {
    const startAngle = valueToAngle(zone.from);
    const endAngle = valueToAngle(zone.to);
    // startAngle > endAngle since angle decreases as value increases.
    const start = pointOnArc(startAngle, radius);
    const end = pointOnArc(endAngle, radius);
    const angleSpan = startAngle - endAngle;
    const largeArcFlag = angleSpan > Math.PI ? 1 : 0;
    // Sweep flag 1 draws clockwise from start to end which matches our
    // decreasing-angle traversal in this y-down coordinate system.
    const pathData = [
      `M ${start.x} ${start.y}`,
      `A ${radius} ${radius} 0 ${largeArcFlag} 1 ${end.x} ${end.y}`
    ].join(' ');
    svg.appendChild(el('path', {
      d: pathData,
      fill: 'none',
      stroke: zone.color,
      'stroke-width': trackWidth,
      'stroke-linecap': 'butt'
    }));
  });

  // Needle.
  const needleAngle = valueToAngle(value);
  const needleLength = radius - trackWidth / 2 - 4;
  const needleTip = pointOnArc(needleAngle, needleLength);
  svg.appendChild(el('line', {
    x1: cx, y1: cy, x2: needleTip.x, y2: needleTip.y,
    stroke: INK_PRIMARY, 'stroke-width': 2, 'stroke-linecap': 'round'
  }));
  svg.appendChild(el('circle', {
    cx, cy, r: 4, fill: INK_PRIMARY
  }));

  if (opts.showValue) {
    svg.appendChild(textEl(cx, cy - radius * 0.35, formatNumber(value), {
      fill: INK_PRIMARY,
      'font-size': '20px',
      'font-weight': '700',
      'text-anchor': 'middle',
      'font-family': 'inherit'
    }));
  }

  if (opts.label) {
    svg.appendChild(textEl(cx, height - 6, opts.label, {
      fill: INK_MUTED,
      'font-size': '11px',
      'text-anchor': 'middle',
      'font-family': 'inherit'
    }));
  }

  container.appendChild(svg);
  return svg;
}

// ─────────────────────────────────────────────────────────────────────────
// Data table
// ─────────────────────────────────────────────────────────────────────────

export function dataTable(container, data, options = {}) {
  const opts = {
    sortable: true,
    filterable: true,
    pageSize: 10,
    title: '',
    ...options
  };

  const state = {
    rows: [...data.rows],
    sortCol: -1,
    sortDir: 'asc',
    filterText: '',
    page: 0
  };

  const wrapper = document.createElement('div');
  wrapper.className = 'dv-data-table';
  wrapper.style.cssText = 'font-family:inherit;';

  if (opts.title) {
    const titleEl = document.createElement('div');
    titleEl.textContent = opts.title;
    titleEl.style.cssText = `font-size:14px;font-weight:600;color:${INK_PRIMARY};margin-bottom:8px;`;
    wrapper.appendChild(titleEl);
  }

  if (opts.filterable) {
    const filterInput = document.createElement('input');
    filterInput.type = 'text';
    filterInput.placeholder = 'Filter...';
    filterInput.style.cssText = `
      width:100%;box-sizing:border-box;padding:6px 10px;margin-bottom:8px;
      border:1px solid ${GRID_COLOR};border-radius:6px;font-size:13px;
      color:${INK_PRIMARY};
    `;
    filterInput.addEventListener('input', () => {
      state.filterText = filterInput.value.toLowerCase();
      state.page = 0;
      render();
    });
    wrapper.appendChild(filterInput);
  }

  const tableWrap = document.createElement('div');
  tableWrap.style.overflowX = 'auto';
  const table = document.createElement('table');
  table.style.cssText = 'width:100%;border-collapse:collapse;font-size:13px;';
  const thead = document.createElement('thead');
  const tbody = document.createElement('tbody');
  table.appendChild(thead);
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  wrapper.appendChild(tableWrap);

  const pagerWrap = document.createElement('div');
  pagerWrap.style.cssText = 'display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:8px;font-size:12px;';
  wrapper.appendChild(pagerWrap);

  function getFilteredSortedRows() {
    let rows = state.rows;
    if (state.filterText) {
      rows = rows.filter((row) =>
        row.some((cell) => String(cell).toLowerCase().includes(state.filterText))
      );
    }
    if (state.sortCol >= 0) {
      rows = [...rows].sort((a, b) => {
        const av = a[state.sortCol];
        const bv = b[state.sortCol];
        const an = parseFloat(av);
        const bn = parseFloat(bv);
        let cmp;
        if (!Number.isNaN(an) && !Number.isNaN(bn) && String(an) === String(av).trim() && String(bn) === String(bv).trim()) {
          cmp = an - bn;
        } else {
          cmp = String(av).localeCompare(String(bv));
        }
        return state.sortDir === 'asc' ? cmp : -cmp;
      });
    }
    return rows;
  }

  function renderHead() {
    thead.innerHTML = '';
    const tr = document.createElement('tr');
    data.headers.forEach((header, colIndex) => {
      const th = document.createElement('th');
      let indicator = '';
      if (opts.sortable && state.sortCol === colIndex) {
        indicator = state.sortDir === 'asc' ? ' ↑' : ' ↓';
      }
      th.textContent = header + indicator;
      th.style.cssText = `
        text-align:left;padding:8px 10px;background:#f9fafb;
        color:${INK_SECONDARY};font-weight:600;border-bottom:2px solid ${GRID_COLOR};
        white-space:nowrap;${opts.sortable ? 'cursor:pointer;user-select:none;' : ''}
      `;
      if (opts.sortable) {
        th.addEventListener('click', () => {
          if (state.sortCol === colIndex) {
            state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
          } else {
            state.sortCol = colIndex;
            state.sortDir = 'asc';
          }
          render();
        });
      }
      tr.appendChild(th);
    });
    thead.appendChild(tr);
  }

  function renderBody() {
    tbody.innerHTML = '';
    const filtered = getFilteredSortedRows();
    const totalPages = Math.max(1, Math.ceil(filtered.length / opts.pageSize));
    if (state.page >= totalPages) state.page = totalPages - 1;
    if (state.page < 0) state.page = 0;

    const startIdx = state.page * opts.pageSize;
    const pageRows = filtered.slice(startIdx, startIdx + opts.pageSize);

    pageRows.forEach((row, i) => {
      const tr = document.createElement('tr');
      tr.style.cssText = `background:${i % 2 === 0 ? '#ffffff' : '#f9fafb'};`;
      tr.addEventListener('mouseenter', () => { tr.style.background = '#eff6ff'; });
      tr.addEventListener('mouseleave', () => { tr.style.background = i % 2 === 0 ? '#ffffff' : '#f9fafb'; });
      row.forEach((cell) => {
        const td = document.createElement('td');
        td.textContent = cell;
        td.style.cssText = `padding:8px 10px;color:${INK_PRIMARY};border-bottom:1px solid ${GRID_COLOR};`;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    renderPager(filtered.length, totalPages);
  }

  function renderPager(totalRows, totalPages) {
    pagerWrap.innerHTML = '';
    if (totalRows <= opts.pageSize) return;

    const makeButton = (label, disabled, onClick) => {
      const btn = document.createElement('button');
      btn.textContent = label;
      btn.disabled = disabled;
      btn.style.cssText = `
        padding:4px 10px;border:1px solid ${GRID_COLOR};border-radius:4px;
        background:${disabled ? '#f3f4f6' : '#ffffff'};
        color:${disabled ? INK_MUTED : INK_SECONDARY};
        cursor:${disabled ? 'default' : 'pointer'};font-size:12px;
      `;
      if (!disabled) btn.addEventListener('click', onClick);
      return btn;
    };

    const prevBtn = makeButton('Prev', state.page === 0, () => {
      state.page -= 1;
      render();
    });
    const nextBtn = makeButton('Next', state.page >= totalPages - 1, () => {
      state.page += 1;
      render();
    });

    const pageIndicator = document.createElement('span');
    pageIndicator.textContent = `Page ${state.page + 1} of ${totalPages}`;
    pageIndicator.style.color = INK_MUTED;

    pagerWrap.appendChild(prevBtn);
    pagerWrap.appendChild(pageIndicator);
    pagerWrap.appendChild(nextBtn);
  }

  function render() {
    renderHead();
    renderBody();
  }

  render();

  clearContainer(container);
  container.appendChild(wrapper);
  return wrapper;
}

// ─────────────────────────────────────────────────────────────────────────
// Stat tile
// ─────────────────────────────────────────────────────────────────────────

export function statTile(container, data) {
  const { value, label, delta, deltaDirection = 'neutral', sparklineValues } = data;

  const card = document.createElement('div');
  card.className = 'dv-stat-tile';
  card.style.cssText = `
    padding:16px 18px;border:1px solid ${GRID_COLOR};border-radius:10px;
    background:#ffffff;font-family:inherit;display:flex;flex-direction:column;gap:4px;
  `;

  const valueEl = document.createElement('div');
  valueEl.textContent = value;
  valueEl.style.cssText = `font-size:2rem;font-weight:700;color:${INK_PRIMARY};line-height:1.1;`;
  card.appendChild(valueEl);

  const labelEl = document.createElement('div');
  labelEl.textContent = label;
  labelEl.style.cssText = `font-size:0.875rem;color:${INK_MUTED};`;
  card.appendChild(labelEl);

  if (delta !== undefined && delta !== null && delta !== '') {
    const deltaRow = document.createElement('div');
    deltaRow.style.cssText = 'display:flex;align-items:center;gap:4px;margin-top:2px;font-size:0.8125rem;font-weight:600;';

    let arrow = '–'; // en dash for neutral
    let color = INK_MUTED;
    if (deltaDirection === 'up') {
      arrow = '↑';
      color = '#059669';
    } else if (deltaDirection === 'down') {
      arrow = '↓';
      color = '#dc2626';
    }

    const arrowEl = document.createElement('span');
    arrowEl.textContent = arrow;
    arrowEl.style.color = color;

    const deltaText = document.createElement('span');
    deltaText.textContent = delta;
    deltaText.style.color = color;

    deltaRow.appendChild(arrowEl);
    deltaRow.appendChild(deltaText);
    card.appendChild(deltaRow);
  }

  if (sparklineValues && sparklineValues.length) {
    const sparkWrap = document.createElement('div');
    sparkWrap.style.marginTop = '6px';
    card.appendChild(sparkWrap);
    sparkline(sparkWrap, sparklineValues, { width: 140, height: 28 });
  }

  clearContainer(container);
  container.appendChild(card);
  return card;
}

// ─────────────────────────────────────────────────────────────────────────
// Demo dashboard
// ─────────────────────────────────────────────────────────────────────────

function sectionCard(titleText) {
  const card = document.createElement('div');
  card.style.cssText = `
    background:#ffffff;border:1px solid ${GRID_COLOR};border-radius:10px;
    padding:16px;font-family:inherit;
  `;
  if (titleText) {
    const heading = document.createElement('h3');
    heading.textContent = titleText;
    heading.style.cssText = `font-size:0.9375rem;font-weight:600;color:${INK_PRIMARY};margin:0 0 12px 0;`;
    card.appendChild(heading);
  }
  const body = document.createElement('div');
  card.appendChild(body);
  return { card, body };
}

export function renderDataViz(main) {
  main.innerHTML = '';

  const wrapper = document.createElement('div');
  wrapper.style.cssText = 'font-family:inherit;padding:16px;';

  const title = document.createElement('h2');
  title.textContent = 'Data Visualization Dashboard';
  title.style.cssText = `font-size:1.375rem;font-weight:700;color:${INK_PRIMARY};margin:0 0 16px 0;`;
  wrapper.appendChild(title);

  const styleTag = document.createElement('style');
  styleTag.textContent = `
    .dv-grid { display:grid; grid-template-columns: 1fr; gap:16px; }
    .dv-stat-row { display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; }
    @media (min-width: 900px) {
      .dv-grid { grid-template-columns: 1fr 1fr; }
      .dv-grid .dv-span-2 { grid-column: span 2; }
    }
    @media (max-width: 640px) {
      .dv-stat-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  `;
  wrapper.appendChild(styleTag);

  // 1. Stat tile row.
  const statRow = document.createElement('div');
  statRow.className = 'dv-stat-row';
  statRow.style.marginBottom = '16px';
  wrapper.appendChild(statRow);

  const statDefs = [
    { value: '1,284', label: 'Active Nodes', delta: '+12%', deltaDirection: 'up', sparklineValues: [12, 18, 15, 22, 28, 24, 31, 29, 35] },
    { value: '47,392', label: 'Threats Blocked', delta: '+8%', deltaDirection: 'up', sparklineValues: [40, 42, 38, 45, 48, 44, 50, 47, 52] },
    { value: '99.97%', label: 'Uptime', delta: '-0.01%', deltaDirection: 'down', sparklineValues: [99.99, 99.98, 99.99, 99.97, 99.98, 99.97, 99.96, 99.97, 99.97] },
    { value: '94.2%', label: 'Scan Coverage', delta: '+3%', deltaDirection: 'up', sparklineValues: [88, 89, 90, 91, 92, 91, 93, 94, 94.2] }
  ];
  statDefs.forEach((def) => {
    const cell = document.createElement('div');
    statRow.appendChild(cell);
    statTile(cell, def);
  });

  // Main grid.
  const grid = document.createElement('div');
  grid.className = 'dv-grid';
  wrapper.appendChild(grid);

  // 2. Bar chart.
  {
    const { card, body } = sectionCard('Top Vulnerability Categories');
    grid.appendChild(card);
    barChart(body, [
      { label: 'SQL Injection', value: 312 },
      { label: 'XSS', value: 276 },
      { label: 'CSRF', value: 198 },
      { label: 'Broken Auth', value: 164 },
      { label: 'Misconfiguration', value: 141 },
      { label: 'Insecure Deserialization', value: 87 }
    ], { width: 480, title: '' });
  }

  // 3. Line chart.
  {
    const { card, body } = sectionCard('Network Traffic (24h)');
    grid.appendChild(card);
    const inbound = [];
    const outbound = [];
    for (let h = 0; h < 24; h++) {
      inbound.push({ x: h, y: Math.round(120 + 80 * Math.sin(h / 3) + 30 * Math.random()) });
      outbound.push({ x: h, y: Math.round(90 + 60 * Math.sin(h / 3 + 1) + 25 * Math.random()) });
    }
    lineChart(body, [
      { label: 'Inbound', points: inbound, color: DEFAULT_PALETTE[0] },
      { label: 'Outbound', points: outbound, color: DEFAULT_PALETTE[1] }
    ], { width: 480, height: 280, xLabel: 'Hour', yLabel: 'Mbps', showArea: true });
  }

  // 4. Pie chart.
  {
    const { card, body } = sectionCard('Alert Severity Distribution');
    grid.appendChild(card);
    pieChart(body, [
      { label: 'Critical', value: 18 },
      { label: 'High', value: 42 },
      { label: 'Medium', value: 96 },
      { label: 'Low', value: 130 },
      { label: 'Info', value: 64 }
    ], { width: 300, height: 340, donut: true });
  }

  // 5. Heatmap.
  {
    const { card, body } = sectionCard('Hourly Attack Frequency');
    grid.appendChild(card);
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const blocks = ['00-02', '02-04', '04-06', '06-08', '08-10', '10-12', '12-14', '14-16', '16-18', '18-20', '20-22', '22-24'];
    const heatData = days.map((_, r) =>
      blocks.map((__, c) => Math.round(10 + 40 * Math.abs(Math.sin((r + 1) * (c + 1) / 6)) + 5 * Math.random()))
    );
    heatmap(body, heatData, {
      rowLabels: days,
      colLabels: blocks,
      cellSize: 36
    });
  }

  // 6. Gauge.
  {
    const { card, body } = sectionCard('System Risk Score');
    grid.appendChild(card);
    body.style.display = 'flex';
    body.style.justifyContent = 'center';
    gauge(body, 62, { width: 220, height: 130, label: 'Composite risk index' });
  }

  // 7. Sparkline row.
  {
    const { card, body } = sectionCard('Recent Trends');
    grid.appendChild(card);
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:24px;flex-wrap:wrap;align-items:flex-end;';
    body.appendChild(row);

    const sparkDefs = [
      { title: 'CPU Load', values: [22, 28, 25, 31, 40, 38, 45, 42, 39], color: DEFAULT_PALETTE[0] },
      { title: 'Memory', values: [60, 62, 58, 65, 70, 68, 72, 74, 71], color: DEFAULT_PALETTE[2] },
      { title: 'Latency (ms)', values: [120, 115, 130, 128, 140, 135, 122, 118, 125], color: DEFAULT_PALETTE[3] }
    ];
    sparkDefs.forEach((def) => {
      const col = document.createElement('div');
      col.style.cssText = 'display:flex;flex-direction:column;gap:4px;';
      const label = document.createElement('div');
      label.textContent = def.title;
      label.style.cssText = `font-size:0.75rem;color:${INK_MUTED};`;
      col.appendChild(label);
      const sparkHolder = document.createElement('div');
      col.appendChild(sparkHolder);
      sparkline(sparkHolder, def.values, { width: 130, height: 32, color: def.color, showMinMax: true });
      row.appendChild(col);
    });
  }

  // 8. Data table (spans full width).
  {
    const { card, body } = sectionCard('Recent Security Events');
    card.classList.add('dv-span-2');
    grid.appendChild(card);
    dataTable(body, {
      headers: ['Timestamp', 'Source IP', 'Event Type', 'Severity', 'Status'],
      rows: [
        ['2026-09-08 03:12', '192.168.1.44', 'Brute Force', 'High', 'Blocked'],
        ['2026-09-08 02:58', '10.0.0.221', 'Port Scan', 'Medium', 'Logged'],
        ['2026-09-08 02:41', '203.0.113.7', 'SQL Injection', 'Critical', 'Blocked'],
        ['2026-09-08 02:20', '198.51.100.9', 'XSS Attempt', 'High', 'Blocked'],
        ['2026-09-08 01:55', '192.168.1.12', 'Malware Beacon', 'Critical', 'Quarantined'],
        ['2026-09-08 01:30', '172.16.0.5', 'DNS Tunneling', 'Medium', 'Logged'],
        ['2026-09-08 01:02', '10.0.0.88', 'Anomalous Login', 'Low', 'Logged'],
        ['2026-09-08 00:47', '203.0.113.19', 'CSRF Attempt', 'Medium', 'Blocked'],
        ['2026-09-08 00:22', '192.168.1.77', 'Data Exfiltration', 'Critical', 'Quarantined'],
        ['2026-09-07 23:59', '198.51.100.44', 'Privilege Escalation', 'High', 'Blocked'],
        ['2026-09-07 23:31', '10.0.0.31', 'Port Scan', 'Low', 'Logged'],
        ['2026-09-07 23:05', '172.16.0.19', 'Ransomware Signature', 'Critical', 'Quarantined']
      ]
    }, { pageSize: 8, title: '' });
  }

  main.appendChild(wrapper);
  return wrapper;
}
