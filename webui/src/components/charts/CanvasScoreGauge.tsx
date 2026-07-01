// ═══════════════════════════════════════════════════
// CanvasScoreGauge - Radial behavioral score gauge
// Canvas 2D, no Recharts. Follows CanvasBarChart pattern.
// Renders a 270-degree arc gauge with color-coded fill.
// ═══════════════════════════════════════════════════

import { useRef, useEffect, useCallback } from 'react';
import { CYBER } from '@/utils/colors';

interface CanvasScoreGaugeProps {
  score: number;           // 0-100
  size?: number;           // diameter in px
  label?: string;
}

function scoreColor(score: number): string {
  if (score >= 80) return CYBER.red;
  if (score >= 60) return CYBER.orange;
  if (score >= 40) return CYBER.yellow;
  return CYBER.green;
}

export default function CanvasScoreGauge({ score, size = 160, label }: CanvasScoreGaugeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const scoreRef = useRef(score);
  scoreRef.current = score;

  const draw = useCallback((w: number, h: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2;
    const cy = h * 0.55;
    const radius = Math.min(w, h) * 0.38;
    const lineWidth = Math.max(8, radius * 0.18);

    const startAngle = Math.PI * 0.8;
    const endAngle = Math.PI * 0.2 + Math.PI * 2; // 270-degree arc
    const totalAngle = endAngle - startAngle;

    const currentScore = Math.min(100, Math.max(0, scoreRef.current));
    const fillAngle = startAngle + (currentScore / 100) * totalAngle;
    const color = scoreColor(currentScore);

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = CYBER.border;
    ctx.lineWidth = lineWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Tick marks every 10 units
    for (let i = 0; i <= 10; i++) {
      const tickAngle = startAngle + (i / 10) * totalAngle;
      const innerR = radius - lineWidth * 0.8;
      const outerR = radius - lineWidth * 0.4;
      const x1 = cx + Math.cos(tickAngle) * innerR;
      const y1 = cy + Math.sin(tickAngle) * innerR;
      const x2 = cx + Math.cos(tickAngle) * outerR;
      const y2 = cy + Math.sin(tickAngle) * outerR;

      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = i >= 8 ? CYBER.red : i >= 6 ? CYBER.orange : CYBER.textDim;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Filled arc
    if (currentScore > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, fillAngle);
      const grad = ctx.createLinearGradient(cx - radius, cy, cx + radius, cy);
      if (currentScore >= 80) {
        grad.addColorStop(0, CYBER.orange);
        grad.addColorStop(1, CYBER.red);
      } else if (currentScore >= 60) {
        grad.addColorStop(0, CYBER.yellow);
        grad.addColorStop(1, CYBER.orange);
      } else {
        grad.addColorStop(0, CYBER.green);
        grad.addColorStop(1, currentScore >= 40 ? CYBER.yellow : CYBER.green);
      }
      ctx.strokeStyle = grad;
      ctx.lineWidth = lineWidth;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Glow effect
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, fillAngle);
      ctx.strokeStyle = color + '40';
      ctx.lineWidth = lineWidth + 6;
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    // Center score number
    ctx.fillStyle = color;
    ctx.font = `bold ${Math.floor(radius * 0.7)}px monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.shadowColor = color;
    ctx.shadowBlur = 12;
    ctx.fillText(String(currentScore), cx, cy);
    ctx.shadowBlur = 0;

    // Label below
    if (label) {
      ctx.fillStyle = CYBER.textMuted;
      ctx.font = `${Math.max(10, Math.floor(radius * 0.3))}px monospace`;
      ctx.textAlign = 'center';
      ctx.fillText(label, cx, cy + radius * 0.6);
    }
  }, [label]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        draw(width, height || size);
      }
    });
    ro.observe(container);
    draw(size, size);
    return () => ro.disconnect();
  }, [draw, size]);

  return (
    <div ref={containerRef} className="flex items-center justify-center" style={{ width: size, height: size }}>
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        style={{ display: 'block' }}
      />
    </div>
  );
}
