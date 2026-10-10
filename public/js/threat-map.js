// Threat Map — D3.js + TopoJSON interactive cyber threat world map
// Renders an SVG world map and plots REAL points: IP addresses resolved to real
// lat/lon/country/city/ISP via ip-api (through the Darknode SSRF-guarded proxy),
// or caller-supplied points. No hardcoded country threat-level/attribution data —
// the base map is neutral geography; every plotted point is resolved from input.

(function() {
  'use strict';

  var _tmWorldData = null;
  var _tmLoading = false;
  var _tmD3Ready = false;
  var _tmTopoReady = false;
  var _tmInstances = {};

  // Neutral land fill — no fabricated hostile/allied/conflict coloring.
  var LAND_FILL = '#101820';

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }

  // Resolve IP addresses to REAL coordinates via ip-api, through the Darknode
  // proxy helper (net.js). Throws if the helper is unavailable; silently skips
  // individual IPs that don't resolve (they simply aren't plotted — never faked).
  function _dnFetchJSON() {
    if (window.dnFetchJSON) return Promise.resolve(window.dnFetchJSON);
    return import('/js/net.js').then(function(m) { return m.dnFetchJSON; });
  }
  function _resolveIPs(ips) {
    return _dnFetchJSON().then(function(dnJSON) {
      if (!dnJSON) throw new Error('Live IP resolution unavailable — the Darknode proxy is not configured.');
      var seen = {};
      var list = (ips || []).map(function(x) { return String(x).trim(); })
        .filter(function(ip) { if (!ip || seen[ip]) return false; seen[ip] = 1; return true; });
      var points = [];
      var chain = Promise.resolve();
      list.forEach(function(ip) {
        chain = chain.then(function() {
          return dnJSON('http://ip-api.com/json/' + encodeURIComponent(ip)).then(function(d) {
            if (d && d.status === 'success' && typeof d.lat === 'number' && typeof d.lon === 'number') {
              points.push({
                id: ip, name: ip, ip: d.query || ip,
                lon: d.lon, lat: d.lat,
                country: d.country, city: d.city, isp: d.isp, org: d.org, as: d.as
              });
            }
          }).catch(function() { /* unresolved IP: skip, do not fabricate */ });
        });
      });
      return chain.then(function() { return points; });
    });
  }

  function _loadScript(url, checkFn, cb) {
    if (checkFn()) { cb(); return; }
    var s = document.createElement('script');
    s.src = url;
    s.onload = function() { cb(); };
    s.onerror = function() { cb(new Error('Failed to load ' + url)); };
    document.head.appendChild(s);
  }

  function _ensureLibs(cb) {
    var pending = 2;
    function done() { if (--pending === 0) cb(); }

    _loadScript(
      '/js/vendor/d3.min.js',
      function() { return typeof d3 !== 'undefined'; },
      function(err) { if (!err) _tmD3Ready = true; done(); }
    );

    _loadScript(
      '/js/vendor/topojson-client.min.js',
      function() { return typeof topojson !== 'undefined'; },
      function(err) { if (!err) _tmTopoReady = true; done(); }
    );
  }

  function _loadWorldData(cb) {
    if (_tmWorldData) { cb(_tmWorldData); return; }
    if (_tmLoading) {
      var check = setInterval(function() {
        if (_tmWorldData) { clearInterval(check); cb(_tmWorldData); }
      }, 100);
      return;
    }
    _tmLoading = true;
    fetch('/js/vendor/countries-110m.json')
      .then(function(r) { return r.json(); })
      .then(function(world) {
        _tmWorldData = world;
        _tmLoading = false;
        cb(world);
      })
      .catch(function() {
        _tmLoading = false;
        cb(null);
      });
  }

  function _getCountryFill() {
    return LAND_FILL;
  }

  function _buildThreatMap(containerId, opts) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var actors = opts.actors || [];
    var arcs = opts.arcs || [];
    var ixps = opts.ixps || [];
    var cables = opts.cables || [];

    var rect = container.getBoundingClientRect();
    var width = opts.width || rect.width || 800;
    var height = opts.height || rect.height || 420;

    if (_tmInstances[containerId]) {
      try { _tmInstances[containerId].cleanup(); } catch(e) {}
    }

    container.innerHTML = '';
    container.style.position = 'relative';
    container.style.overflow = 'hidden';
    container.style.background = 'var(--card,#0b1120)';

    var svg = d3.select('#' + containerId)
      .append('svg')
      .attr('width', width)
      .attr('height', height)
      .style('background', 'var(--card,#0b1120)')
      .style('display', 'block');

    var defs = svg.append('defs');

    // Glow filter for threat dots
    var glowFilter = defs.append('filter').attr('id', 'tm-glow');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
    var merge = glowFilter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arc glow
    var arcGlow = defs.append('filter').attr('id', 'tm-arc-glow');
    arcGlow.append('feGaussianBlur').attr('stdDeviation', '2').attr('result', 'blur');
    var arcMerge = arcGlow.append('feMerge');
    arcMerge.append('feMergeNode').attr('in', 'blur');
    arcMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    var g = svg.append('g');

    // Projection
    var projection = d3.geoNaturalEarth1()
      .scale(width / 5.8)
      .translate([width / 2, height / 2]);

    var path = d3.geoPath().projection(projection);

    // Zoom
    var zoom = d3.zoom()
      .scaleExtent([1, 12])
      .on('zoom', function(event) {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Tooltip
    var tooltip = d3.select('#' + containerId)
      .append('div')
      .style('position', 'absolute')
      .style('background', 'var(--card2,#0f1726)')
      .style('border', '1px solid var(--line,#283a5a)')
      .style('border-radius', '4px')
      .style('padding', '10px 14px')
      .style('font-family', "'Segoe UI',system-ui,sans-serif")
      .style('font-size', '10px')
      .style('color', 'var(--txt,#e7eefc)')
      .style('pointer-events', 'none')
      .style('z-index', '100')
      .style('max-width', '280px')
      .style('box-shadow', '0 4px 20px rgba(0,0,0,0.6)')
      .style('display', 'none');

    // Actor detail popup
    var popup = d3.select('#' + containerId)
      .append('div')
      .attr('id', 'tm-popup')
      .style('position', 'absolute')
      .style('background', 'var(--card2,#0f1726)')
      .style('border', '1px solid var(--line,#283a5a)')
      .style('border-radius', '6px')
      .style('padding', '14px 18px')
      .style('font-family', "'Segoe UI',system-ui,sans-serif")
      .style('font-size', '11px')
      .style('color', 'var(--txt,#e7eefc)')
      .style('pointer-events', 'auto')
      .style('z-index', '200')
      .style('max-width', '360px')
      .style('box-shadow', '0 4px 24px rgba(0,0,0,0.7)')
      .style('display', 'none');

    // Render world
    var countries = topojson.feature(_tmWorldData, _tmWorldData.objects.countries);

    // Ocean
    g.append('rect')
      .attr('width', width * 4)
      .attr('height', height * 4)
      .attr('x', -width * 1.5)
      .attr('y', -height * 1.5)
      .attr('fill', '#060a10');

    // Graticule
    var graticule = d3.geoGraticule();
    g.append('path')
      .datum(graticule())
      .attr('d', path)
      .attr('fill', 'none')
      .attr('stroke', '#0d1a28')
      .attr('stroke-width', 0.3);

    // Countries
    g.selectAll('.tm-country')
      .data(countries.features)
      .enter()
      .append('path')
      .attr('class', 'tm-country')
      .attr('d', path)
      .attr('fill', function() { return _getCountryFill(); })
      .attr('stroke', '#0a2a44')
      .attr('stroke-width', 0.5)
      .style('cursor', 'default')
      .on('mouseover', function(event, d) {
        d3.select(this).attr('stroke', '#2563eb').attr('stroke-width', 1.2);
        // Country name comes from the map dataset's own properties (factual
        // geography), not from any hardcoded threat list.
        var name = (d && d.properties && d.properties.name) ? d.properties.name : '';
        if (!name) return;
        tooltip.html('<div style="color:var(--acc,#2563eb);font-weight:bold;font-size:12px;letter-spacing:1px;">' + _esc(name) + '</div>').style('display', 'block');
        var pos = d3.pointer(event, container);
        tooltip.style('left', Math.min(pos[0] + 12, width - 290) + 'px')
               .style('top', Math.max(pos[1] - 60, 4) + 'px');
      })
      .on('mousemove', function(event) {
        var pos = d3.pointer(event, container);
        tooltip.style('left', Math.min(pos[0] + 12, width - 290) + 'px')
               .style('top', Math.max(pos[1] - 60, 4) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this).attr('stroke', '#0a2a44').attr('stroke-width', 0.5);
        tooltip.style('display', 'none');
      });

    // Borders
    g.append('path')
      .datum(topojson.mesh(_tmWorldData, _tmWorldData.objects.countries, function(a, b) { return a !== b; }))
      .attr('d', path)
      .attr('fill', 'none')
      .attr('stroke', '#0a2a44')
      .attr('stroke-width', 0.4);

    // --- UNDERSEA CABLES ---
    if (cables.length > 0) {
      var cableGroup = g.append('g').attr('class', 'tm-cables');
      cables.forEach(function(cable) {
        var coords = [[cable.from.lon, cable.from.lat], [cable.to.lon, cable.to.lat]];
        var lineGen = d3.geoPath().projection(projection);
        var geojson = { type: 'Feature', geometry: { type: 'LineString', coordinates: coords } };
        cableGroup.append('path')
          .datum(geojson)
          .attr('d', lineGen)
          .attr('fill', 'none')
          .attr('stroke', '#0d3a2a')
          .attr('stroke-width', 0.8)
          .attr('stroke-dasharray', '4,3')
          .attr('opacity', 0.5);
      });
    }

    // --- IXP DOTS ---
    if (ixps.length > 0) {
      var ixpGroup = g.append('g').attr('class', 'tm-ixps');
      ixps.forEach(function(ixp) {
        var pt = projection([ixp.lon, ixp.lat]);
        if (!pt) return;
        ixpGroup.append('circle')
          .attr('cx', pt[0])
          .attr('cy', pt[1])
          .attr('r', 3)
          .attr('fill', '#00ff88')
          .attr('opacity', 0.6)
          .attr('filter', 'url(#tm-glow)');
      });
    }

    // --- ATTACK ARCS ---
    var arcGroup = g.append('g').attr('class', 'tm-arcs');
    var arcPaths = [];
    arcs.forEach(function(arc) {
      var fromLon, fromLat, toLon, toLat;
      // Explicit coordinate arcs (e.g. resolved IP -> IP) take precedence.
      if (typeof arc.fromLon === 'number' && typeof arc.fromLat === 'number') {
        fromLon = arc.fromLon; fromLat = arc.fromLat;
      } else {
        var fromActor = null;
        for (var a = 0; a < actors.length; a++) {
          if (actors[a].id === arc.from) { fromActor = actors[a]; break; }
        }
        if (!fromActor) return;
        fromLon = fromActor.lon; fromLat = fromActor.lat;
      }
      if (typeof arc.toLon === 'number' && typeof arc.toLat === 'number') {
        toLon = arc.toLon; toLat = arc.toLat;
      } else if (arc.to) {
        var toActor = null;
        for (var b = 0; b < actors.length; b++) {
          if (actors[b].id === arc.to) { toActor = actors[b]; break; }
        }
        if (!toActor) return;
        toLon = toActor.lon; toLat = toActor.lat;
      } else { return; }

      var coords = [[fromLon, fromLat], [toLon, toLat]];
      var geojson = { type: 'Feature', geometry: { type: 'LineString', coordinates: coords } };
      var lineGen = d3.geoPath().projection(projection);

      var arcPath = arcGroup.append('path')
        .datum(geojson)
        .attr('d', lineGen)
        .attr('fill', 'none')
        .attr('stroke', arc.color || '#ff3333')
        .attr('stroke-width', 1.2)
        .attr('stroke-dasharray', '6,4')
        .attr('opacity', 0.5)
        .attr('filter', 'url(#tm-arc-glow)');

      arcPaths.push(arcPath);
    });

    // --- THREAT ACTOR DOTS ---
    var dotGroup = g.append('g').attr('class', 'tm-actors');
    var pulseDots = [];

    actors.forEach(function(actor) {
      var pt = projection([actor.lon, actor.lat]);
      if (!pt) return;

      var isHostile = actor.alignment === 'hostile';
      var color = actor.color || (isHostile ? '#ff3333' : '#4488ff');
      var radius = actor.tier === 'TIER-1' ? 6 : 4;

      // Outer pulse ring
      var pulse = dotGroup.append('circle')
        .attr('cx', pt[0])
        .attr('cy', pt[1])
        .attr('r', radius)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', 1)
        .attr('opacity', 0.6);

      pulseDots.push({ el: pulse, baseR: radius, color: color });

      // Core dot
      dotGroup.append('circle')
        .attr('cx', pt[0])
        .attr('cy', pt[1])
        .attr('r', radius * 0.6)
        .attr('fill', color)
        .attr('filter', 'url(#tm-glow)')
        .style('cursor', 'pointer')
        .on('click', function(event) {
          event.stopPropagation();
          // Field-driven: render only attributes actually present on the point.
          // For resolved IPs these are real ip-api fields (IP, country, city,
          // ISP, org, AS). Nothing is invented.
          var h = '<div style="position:absolute;top:6px;right:10px;color:var(--mut,#7a93b8);cursor:pointer;font-size:16px;" onclick="document.getElementById(\'tm-popup\').style.display=\'none\'">x</div>';
          h += '<div style="color:' + color + ';font-weight:bold;font-size:13px;letter-spacing:1px;margin-bottom:6px;padding-right:20px;">' + _esc(actor.name || actor.id || 'Point') + '</div>';
          function row(label, val) {
            if (val === undefined || val === null || val === '') return '';
            return '<div style="margin:3px 0;"><span style="color:var(--txt-2,#9fb0cc);">' + _esc(label) + ':</span> <span style="color:var(--txt,#e7eefc);font-size:10px;">' + _esc(val) + '</span></div>';
          }
          h += row('IP', actor.ip);
          h += row('COUNTRY', actor.country);
          h += row('CITY', actor.city);
          h += row('ISP', actor.isp);
          h += row('ORG', actor.org);
          h += row('AS', actor.as);
          // Legacy caller-supplied fields (rendered only if provided).
          h += row('NATION', actor.nation);
          h += row('TIER', actor.tier);
          h += row('APT GROUPS', actor.aptGroups);
          h += row('RECENT OPS', actor.recentOps);
          h += row('CAPABILITIES', actor.capabilities);
          h += row('NOTE', actor.notes);

          popup.html(h).style('display', 'block');
          var pos = d3.pointer(event, container);
          popup.style('left', Math.min(pos[0] + 10, width - 380) + 'px')
               .style('top', Math.max(pos[1] - 100, 4) + 'px');
        });

      // Label
      if (actor.tier === 'TIER-1') {
        dotGroup.append('text')
          .attr('x', pt[0])
          .attr('y', pt[1] - radius - 4)
          .attr('text-anchor', 'middle')
          .attr('fill', color)
          .attr('font-family', "'Segoe UI',system-ui,sans-serif")
          .attr('font-size', '8px')
          .attr('opacity', 0.7)
          .text(actor.id.toUpperCase());
      }
    });

    // Close popup on background click
    svg.on('click', function() {
      popup.style('display', 'none');
    });

    // --- ANIMATIONS ---
    var animRunning = true;
    var startTime = Date.now();

    function animate() {
      if (!animRunning) return;
      var elapsed = (Date.now() - startTime) / 1000;

      // Pulse threat dots
      for (var i = 0; i < pulseDots.length; i++) {
        var pd = pulseDots[i];
        var phase = (elapsed * 0.8 + i * 0.3) % 1;
        var r = pd.baseR + pd.baseR * 1.5 * phase;
        var alpha = 0.6 * (1 - phase);
        pd.el.attr('r', r).attr('opacity', alpha);
      }

      // Animate arc dashes
      for (var j = 0; j < arcPaths.length; j++) {
        var offset = (elapsed * 15 + j * 5) % 20;
        arcPaths[j].attr('stroke-dashoffset', -offset);
        var arcAlpha = 0.3 + 0.3 * Math.abs(Math.sin(elapsed * 0.5 + j * 0.4));
        arcPaths[j].attr('opacity', arcAlpha);
      }

      requestAnimationFrame(animate);
    }
    animate();

    // Cleanup function
    _tmInstances[containerId] = {
      cleanup: function() {
        animRunning = false;
        // resizeHandler/resizeTimer are var-hoisted and assigned below; by the
        // time cleanup runs they exist. Dropping the listener here is what stops
        // each rebuild (and each SENTINEL EYE revisit) from stacking another
        // resize handler and doubling the rebuild work on every resize.
        if (resizeTimer) clearTimeout(resizeTimer);
        window.removeEventListener('resize', resizeHandler);
        container.innerHTML = '';
      }
    };

    // Resize handler
    var resizeTimer = null;
    var resizeHandler = function() {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        var newRect = container.getBoundingClientRect();
        if (newRect.width > 0 && newRect.width !== width) {
          _buildThreatMap(containerId, opts);
        }
      }, 300);
    };
    window.addEventListener('resize', resizeHandler);
  }

  // --- PUBLIC API ---
  window.renderThreatMap = function(containerId, opts) {
    opts = opts || {};
    var container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--acc,#2563eb);font-size:12px;letter-spacing:2px;">LOADING THREAT MAP...</div>';

    _ensureLibs(function() {
      if (!_tmD3Ready || !_tmTopoReady) {
        container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--bad,#dc2626);font-size:11px;">Failed to load D3.js or TopoJSON from CDN</div>';
        return;
      }
      _loadWorldData(function(world) {
        if (!world) {
          container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--bad,#dc2626);font-size:11px;">Failed to load world map data</div>';
          return;
        }
        // Real-data path: resolve supplied IPs to real coordinates via ip-api
        // before building. Each resolved point becomes a map marker.
        if (opts.ips && opts.ips.length) {
          container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--acc,#2563eb);font-size:12px;letter-spacing:2px;">RESOLVING ' + opts.ips.length + ' IP ADDRESSES...</div>';
          _resolveIPs(opts.ips).then(function(points) {
            if (!points.length) {
              container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--warn,#d97706);font-size:11px;text-align:center;padding:0 20px;">No IP addresses resolved to a location. Nothing is plotted — results are never fabricated.</div>';
              return;
            }
            var merged = {};
            merged.actors = (opts.actors || []).concat(points);
            merged.arcs = opts.arcs || [];
            merged.ixps = opts.ixps || [];
            merged.cables = opts.cables || [];
            merged.width = opts.width; merged.height = opts.height;
            _buildThreatMap(containerId, merged);
          }).catch(function(err) {
            container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:system-ui,sans-serif;color:var(--bad,#dc2626);font-size:11px;text-align:center;padding:0 20px;">' + _esc((err && err.message) ? err.message : 'IP resolution failed') + '</div>';
          });
          return;
        }
        _buildThreatMap(containerId, opts);
      });
    });
  };

  // Convenience entry point: plot a list of IP addresses as real points.
  //   window.plotThreatMapIPs('container-id', ['8.8.8.8','1.1.1.1'], { arcs: [...] })
  window.plotThreatMapIPs = function(containerId, ips, opts) {
    opts = opts || {};
    opts.ips = ips || [];
    return window.renderThreatMap(containerId, opts);
  };

  window.destroyThreatMap = function(containerId) {
    if (_tmInstances[containerId]) {
      _tmInstances[containerId].cleanup();
      delete _tmInstances[containerId];
    }
  };
})();
