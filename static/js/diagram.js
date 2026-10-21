/**
 * diagram.js — STRIDE Threat Model Analyzer
 * Renders the system architecture diagram on an HTML5 Canvas.
 * Reads window.SYSTEM_DATA set by the diagram.html template.
 */

'use strict';

(function () {
  // ── Colour palette (matches CSS variables) ──────────────────────────────
  var COLORS = {
    bg:       '#0d1117',
    card:     '#161b22',
    border:   '#30363d',
    text:     '#c9d1d9',
    textStrong: '#f0f6fc',
    muted:    '#8b949e',
    cyan:     '#58a6ff',
    cyanDark: '#1f6feb',
    green:    '#3fb950',
    yellow:   '#d29922',
    red:      '#f85149',
    purple:   '#bc8cff',
    orange:   '#e3b341',
  };

  // ── Component type → colour ──────────────────────────────────────────────
  var TYPE_COLOR = {
    user:             COLORS.cyan,
    web_application:  COLORS.green,
    database:         COLORS.yellow,
    external_api:     COLORS.purple,
    mobile_app:       COLORS.orange,
    message_queue:    COLORS.red,
    file_server:      COLORS.muted,
  };

  // ── Component type → icon character ─────────────────────────────────────
  var TYPE_ICON = {
    user:             '👤',
    web_application:  '🖥',
    database:         '🗄',
    external_api:     '🔌',
    mobile_app:       '📱',
    message_queue:    '📨',
    file_server:      '📁',
  };

  // ── Layout helpers ───────────────────────────────────────────────────────
  var NODE_W = 130;
  var NODE_H = 60;
  var PAD    = 40;

  /**
   * Assign (x, y) positions to components in a circular layout so that
   * nodes are evenly distributed and data flow arrows look clean.
   */
  function layoutComponents(components, canvasW, canvasH) {
    var n   = components.length;
    var cx  = canvasW / 2;
    var cy  = canvasH / 2;
    var r   = Math.min(cx, cy) - NODE_W / 2 - PAD;

    return components.map(function (comp, i) {
      var angle;
      if (n === 1) {
        angle = 0;
      } else if (n === 2) {
        angle = i === 0 ? Math.PI / 2 : (3 * Math.PI) / 2;
      } else {
        // Start at top (-90°) and go clockwise
        angle = (2 * Math.PI * i) / n - Math.PI / 2;
      }
      return {
        comp:  comp,
        x:     cx + r * Math.cos(angle),
        y:     cy + r * Math.sin(angle),
        color: TYPE_COLOR[comp.type] || COLORS.muted,
        icon:  TYPE_ICON[comp.type]  || '⬜',
      };
    });
  }

  /**
   * Find the node layout object for a given component id or name.
   */
  function findNode(nodes, idOrName) {
    return nodes.find(function (n) {
      return n.comp.id === idOrName ||
             n.comp.name.toLowerCase() === idOrName.toLowerCase();
    });
  }

  /**
   * Draw a rounded rectangle.
   */
  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  /**
   * Draw an arrowhead at (x2, y2) pointing from (x1, y1).
   */
  function drawArrow(ctx, x1, y1, x2, y2) {
    var headLen = 10;
    var angle   = Math.atan2(y2 - y1, x2 - x1);
    ctx.beginPath();
    ctx.moveTo(x2, y2);
    ctx.lineTo(
      x2 - headLen * Math.cos(angle - Math.PI / 7),
      y2 - headLen * Math.sin(angle - Math.PI / 7)
    );
    ctx.lineTo(
      x2 - headLen * Math.cos(angle + Math.PI / 7),
      y2 - headLen * Math.sin(angle + Math.PI / 7)
    );
    ctx.closePath();
    ctx.fill();
  }

  /**
   * Get the edge point of a node box in the direction of (tx, ty).
   */
  function nodeEdgePoint(node, tx, ty) {
    var dx = tx - node.x;
    var dy = ty - node.y;
    var hw = NODE_W / 2;
    var hh = NODE_H / 2;
    var t  = Math.min(Math.abs(hw / dx), Math.abs(hh / dy));
    return {
      x: node.x + dx * t,
      y: node.y + dy * t,
    };
  }

  /**
   * Main render function.
   */
  function render(system) {
    var canvas = document.getElementById('diagramCanvas');
    if (!canvas) return;

    // Size the canvas
    var containerW = canvas.parentElement.clientWidth || 900;
    var canvasW    = containerW;
    var canvasH    = Math.max(420, Math.min(600, containerW * 0.55));
    canvas.width   = canvasW;
    canvas.height  = canvasH;

    var ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvasW, canvasH);

    // Background
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, canvasW, canvasH);

    var components = system.components || [];
    var dataFlows  = system.data_flows  || [];
    var boundaries = system.trust_boundaries || [];

    var nodes = layoutComponents(components, canvasW, canvasH);

    // ── Draw trust boundary zones ────────────────────────────────────────
    boundaries.forEach(function (tb, i) {
      // Draw a dashed rectangle encompassing the nodes referenced (or a
      // decorative zone based on position to keep it simple & visual).
      var margin = 28;
      var zoneW = canvasW - margin * 2 * (i + 1);
      var zoneH = canvasH - margin * 2 * (i + 1);
      var zoneX = margin * (i + 1);
      var zoneY = margin * (i + 1);
      ctx.save();
      ctx.setLineDash([6, 4]);
      ctx.strokeStyle = 'rgba(248,81,73,0.35)';
      ctx.lineWidth = 1.5;
      roundRect(ctx, zoneX, zoneY, zoneW, zoneH, 12);
      ctx.stroke();
      ctx.setLineDash([]);

      // Boundary label
      ctx.fillStyle = 'rgba(248,81,73,0.6)';
      ctx.font = '11px -apple-system, Segoe UI, sans-serif';
      ctx.fillText(tb.name, zoneX + 8, zoneY + 15);
      ctx.restore();
    });

    // ── Draw data flow arrows ────────────────────────────────────────────
    dataFlows.forEach(function (df) {
      var fromNode = findNode(nodes, df.from);
      var toNode   = findNode(nodes, df.to);
      if (!fromNode || !toNode) return;

      var ep1 = nodeEdgePoint(fromNode, toNode.x, toNode.y);
      var ep2 = nodeEdgePoint(toNode,   fromNode.x, fromNode.y);

      ctx.save();
      ctx.strokeStyle = COLORS.cyan;
      ctx.lineWidth   = 1.5;
      ctx.globalAlpha = 0.6;
      ctx.beginPath();
      ctx.moveTo(ep1.x, ep1.y);
      ctx.lineTo(ep2.x, ep2.y);
      ctx.stroke();

      // Arrow head
      ctx.globalAlpha = 0.9;
      ctx.fillStyle   = COLORS.cyan;
      drawArrow(ctx, ep1.x, ep1.y, ep2.x, ep2.y);

      // Flow label (midpoint)
      var midX = (ep1.x + ep2.x) / 2;
      var midY = (ep1.y + ep2.y) / 2;
      if (df.label) {
        ctx.globalAlpha = 0.85;
        ctx.fillStyle   = COLORS.bg;
        var labelW = Math.min(120, df.label.length * 6.5 + 10);
        ctx.fillRect(midX - labelW / 2, midY - 9, labelW, 14);
        ctx.fillStyle = COLORS.muted;
        ctx.font      = '10px -apple-system, Segoe UI, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(
          df.label.length > 20 ? df.label.substring(0, 18) + '…' : df.label,
          midX, midY + 3
        );
      }
      ctx.restore();
    });

    // ── Draw component nodes ─────────────────────────────────────────────
    nodes.forEach(function (node) {
      var x = node.x - NODE_W / 2;
      var y = node.y - NODE_H / 2;
      var color = node.color;

      ctx.save();

      // Shadow
      ctx.shadowColor = color + '44';
      ctx.shadowBlur  = 12;

      // Node box background
      ctx.fillStyle = COLORS.card;
      roundRect(ctx, x, y, NODE_W, NODE_H, 8);
      ctx.fill();

      // Border
      ctx.strokeStyle = color;
      ctx.lineWidth   = 2;
      ctx.shadowBlur  = 0;
      roundRect(ctx, x, y, NODE_W, NODE_H, 8);
      ctx.stroke();

      ctx.restore();

      // Icon
      ctx.font      = '20px serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.icon, node.x, node.y - 6);

      // Component name
      var name = node.comp.name;
      if (name.length > 16) name = name.substring(0, 14) + '…';
      ctx.fillStyle = COLORS.textStrong;
      ctx.font      = '11px -apple-system, Segoe UI, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(name, node.x, node.y + 14);

      // Type label
      ctx.fillStyle = color;
      ctx.font      = 'bold 9px -apple-system, Segoe UI, sans-serif';
      ctx.fillText(
        (node.comp.type || '').replace(/_/g, ' ').toUpperCase(),
        node.x,
        node.y + 26
      );
    });
  }

  // ── Initialise ─────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    var system = window.SYSTEM_DATA;
    if (!system) return;

    render(system);

    // Re-render on window resize
    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () { render(system); }, 200);
    });
  });
})();
