import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

/// The signature element: a faint mesh of nodes + edges behind the UI.
/// Violet and still when the node is offline; teal and gently pulsing when
/// it's online. Embodies the "lattice" topology and reflects live state.
class LatticeMesh extends StatefulWidget {
  const LatticeMesh({super.key, required this.active, this.child});

  final bool active;
  final Widget? child;

  @override
  State<LatticeMesh> createState() => _LatticeMeshState();
}

class _LatticeMeshState extends State<LatticeMesh>
    with SingleTickerProviderStateMixin {
  late final AnimationController _c =
      AnimationController(vsync: this, duration: const Duration(seconds: 8));
  late final List<Offset> _nodes;
  late final List<List<int>> _edges;

  @override
  void initState() {
    super.initState();
    final rng = math.Random(0x1A77);
    _nodes = List.generate(26, (_) => Offset(rng.nextDouble(), rng.nextDouble()));
    _edges = List.generate(_nodes.length, (i) {
      final dists = List.generate(_nodes.length, (j) => (i, j, (_nodes[i] - _nodes[j]).distance))
          .where((t) => t.$1 != t.$2)
          .toList()
        ..sort((a, b) => a.$3.compareTo(b.$3));
      return dists.take(2).map((t) => t.$2).toList();
    });
    if (widget.active) _c.repeat();
  }

  @override
  void didUpdateWidget(LatticeMesh old) {
    super.didUpdateWidget(old);
    final reduceMotion = MediaQuery.maybeOf(context)?.disableAnimations ?? false;
    if (widget.active && !reduceMotion) {
      if (!_c.isAnimating) _c.repeat();
    } else {
      _c.stop();
    }
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      fit: StackFit.expand,
      children: [
        AnimatedBuilder(
          animation: _c,
          builder: (_, _) => CustomPaint(
            painter: _MeshPainter(
              nodes: _nodes,
              edges: _edges,
              phase: _c.value,
              active: widget.active,
            ),
          ),
        ),
        if (widget.child != null) widget.child!,
      ],
    );
  }
}

class _MeshPainter extends CustomPainter {
  _MeshPainter({
    required this.nodes,
    required this.edges,
    required this.phase,
    required this.active,
  });

  final List<Offset> nodes;
  final List<List<int>> edges;
  final double phase;
  final bool active;

  @override
  void paint(Canvas canvas, Size size) {
    final accent = active ? Lx.teal : Lx.violet;
    final pts = nodes.map((n) => Offset(n.dx * size.width, n.dy * size.height)).toList();

    final edgePaint = Paint()
      ..color = accent.withValues(alpha: active ? 0.10 : 0.06)
      ..strokeWidth = 1;
    for (var i = 0; i < edges.length; i++) {
      for (final j in edges[i]) {
        canvas.drawLine(pts[i], pts[j], edgePaint);
      }
    }

    for (var i = 0; i < pts.length; i++) {
      // A slow pulse travels through the nodes when online.
      final pulse = active
          ? (0.5 + 0.5 * math.sin(phase * 2 * math.pi + i * 0.6))
          : 0.25;
      final r = 1.6 + pulse * (active ? 2.2 : 0.8);
      canvas.drawCircle(
        pts[i],
        r,
        Paint()..color = accent.withValues(alpha: active ? 0.12 + pulse * 0.25 : 0.10),
      );
    }
  }

  @override
  bool shouldRepaint(_MeshPainter old) =>
      old.phase != phase || old.active != active;
}
