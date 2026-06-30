import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../theme.dart';

/// A raised instrument panel container with a hairline border.
class Panel extends StatelessWidget {
  const Panel({super.key, required this.child, this.padding = const EdgeInsets.all(20)});

  final Widget child;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: Lx.raised,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Lx.line),
      ),
      child: child,
    );
  }
}

/// Small uppercase eyebrow label, optionally tinted to a signal color.
class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key, this.color = Lx.muted});

  final String text;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Text(
      text.toUpperCase(),
      style: mono(size: 11, color: color, weight: FontWeight.w700, spacing: 1.6),
    );
  }
}

/// A monospace data value with a tap-to-copy affordance.
class CopyableValue extends StatelessWidget {
  const CopyableValue({
    super.key,
    required this.value,
    this.display,
    this.style,
    this.toast = 'Copied',
  });

  final String value;
  final String? display;
  final TextStyle? style;
  final String toast;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(8),
      onTap: () {
        Clipboard.setData(ClipboardData(text: value));
        ScaffoldMessenger.of(context)
          ..clearSnackBars()
          ..showSnackBar(SnackBar(content: Text(toast), duration: const Duration(seconds: 1)));
      },
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(child: Text(display ?? value, style: style ?? mono())),
            const SizedBox(width: 10),
            const Icon(Icons.content_copy_rounded, size: 15, color: Lx.muted),
          ],
        ),
      ),
    );
  }
}

/// The instrument power switch — drives the listen toggle. Glows teal when live.
class PowerToggle extends StatelessWidget {
  const PowerToggle({super.key, required this.on, required this.busy, required this.onChanged});

  final bool on;
  final bool busy;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) {
    final color = on ? Lx.teal : Lx.muted;
    return InkWell(
      borderRadius: BorderRadius.circular(14),
      onTap: busy ? null : onChanged,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 220),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        decoration: BoxDecoration(
          color: on ? Lx.teal.withValues(alpha: 0.08) : Lx.raisedHi,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: on ? Lx.teal.withValues(alpha: 0.5) : Lx.line),
          boxShadow: on
              ? [BoxShadow(color: Lx.teal.withValues(alpha: 0.25), blurRadius: 18, spreadRadius: -4)]
              : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            busy
                ? const SizedBox(
                    width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : Icon(on ? Icons.sensors_rounded : Icons.sensors_off_rounded, color: color, size: 18),
            const SizedBox(width: 10),
            Text(on ? 'ONLINE' : 'OFFLINE',
                style: mono(size: 13, color: color, weight: FontWeight.w700, spacing: 1.2)),
          ],
        ),
      ),
    );
  }
}
